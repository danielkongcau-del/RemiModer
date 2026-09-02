#include "runtime.h"
#include <cstring>
#include <functional>
#include <new>
#include <thread>
#include <future>
#include <sddl.h>

#pragma comment(lib,"Advapi32.lib")

namespace {
uc::Runtime* runtime=nullptr;
std::mutex controlMutex;
std::unordered_map<std::string,std::pair<std::string,uc::Json>> completed;
std::string bootstrapError;
uc::Json pendingPlan;
std::string pendingRequestId;
std::mutex pendingMutex;

struct PipeSecurity {
    SECURITY_ATTRIBUTES attributes{};
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    PipeSecurity(){
        HANDLE rawToken=nullptr;uc::Require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&rawToken)!=FALSE,
            "control pipe token query failed");
        struct TokenCloser {HANDLE value;~TokenCloser(){if(value)CloseHandle(value);}} token{rawToken};
        DWORD bytes=0;GetTokenInformation(rawToken,TokenUser,nullptr,0,&bytes);
        uc::Require(bytes&&GetLastError()==ERROR_INSUFFICIENT_BUFFER,"control pipe token size query failed");
        std::vector<unsigned char> buffer(bytes);
        uc::Require(GetTokenInformation(rawToken,TokenUser,buffer.data(),bytes,&bytes)!=FALSE,
            "control pipe token identity query failed");
        auto* user=(TOKEN_USER*)buffer.data();LPWSTR rawSid=nullptr;
        uc::Require(ConvertSidToStringSidW(user->User.Sid,&rawSid)!=FALSE,"control pipe SID conversion failed");
        struct LocalCloser {HLOCAL value;~LocalCloser(){if(value)LocalFree(value);}} sid{rawSid};
        // DACL: only this process user and SYSTEM. A medium mandatory label is
        // sufficient for the normal medium controller -> elevated observer
        // path while denying writes from same-user low-integrity processes.
        // Remote clients remain rejected by PIPE_REJECT_REMOTE_CLIENTS below.
        std::wstring sddl=L"D:P(A;;GA;;;SY)(A;;GA;;;"+std::wstring(rawSid)+L")S:(ML;;NW;;;ME)";
        uc::Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,
            &descriptor,nullptr)!=FALSE,"control pipe security descriptor creation failed");
        attributes.nLength=sizeof(attributes);attributes.lpSecurityDescriptor=descriptor;
        attributes.bInheritHandle=FALSE;
    }
    ~PipeSecurity(){if(descriptor)LocalFree(descriptor);}
};

HANDLE CreateControlPipe(const wchar_t* name,PipeSecurity& security){
    return CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,
        &security.attributes);
}

uc::Json Handle(const uc::Json& request){
    using namespace uc;std::string id=request.at("request_id"),command=request.at("command");
    Require(!id.empty(),"request id required");auto text=request.dump();auto hash=Sha(text.data(),text.size());
    bool mutation=command=="apply"||command=="start"||command=="stop"||command=="mark"||command=="qualify-sites";
    std::lock_guard lock(controlMutex);
    if(mutation&&completed.contains(id)){auto& prior=completed.at(id);Require(prior.first==hash,"request id reused with different command");return prior.second;}
    // Reserve the receipt before any side effect. Even an exception after a
    // successful publication cannot make an identical retry activate twice.
    if(mutation)completed.emplace(id,std::make_pair(hash,Json{{"ok",false},{"request_id",id},
        {"state","EXECUTION_UNCERTAIN"},{"error","query status; request will not be executed twice"}}));
    Json result;
    try{
    if(command=="capabilities")result={{"ok",true},{"capabilities",runtime->Capabilities()}};
    else if(command=="status"){result=runtime->Status();std::lock_guard pl(pendingMutex);result["bootstrap_error"]=bootstrapError;result["waiting_plan"]=!pendingPlan.is_null();}
    else if(command=="validate"){
        auto compiled=Compile(request.at("plan"),[](uint64_t at){return runtime->SlotOriginal(at);});
        result={{"ok",true},{"plan_hash",compiled->planHash},{"bindings",compiled->bindings},{"activated",false}};
    }
    else if(command=="apply"){
        const auto& plan=request.at("plan");
        {std::lock_guard pl(pendingMutex);Require(pendingPlan.is_null()||pendingRequestId==id,
            "another capture plan is already waiting for module availability");}
        try{auto compiled=Compile(plan,[](uint64_t at){return runtime->SlotOriginal(at);});result=runtime->Apply(std::move(compiled));std::lock_guard pl(pendingMutex);pendingPlan=nullptr;pendingRequestId.clear();bootstrapError.clear();}
        catch(const std::exception& e){auto error=std::string(e.what());if(error.rfind("WAITING_",0)!=0)throw;
            std::lock_guard pl(pendingMutex);pendingPlan=plan;pendingRequestId=id;bootstrapError=e.what();result={{"ok",true},{"state",error.substr(0,error.find(':'))},{"note","apply is pending module availability; poll status until waiting_plan is false"}};}
    }else if(command=="start"){runtime->Start();result={{"ok",true},{"accepted",true}};}
    else if(command=="qualify-sites")result=runtime->QualifySites(request.at("qualification"));
    else if(command=="stop"){runtime->Stop(request.value("force",Json(false)).get<bool>());std::lock_guard pl(pendingMutex);
        if(!pendingRequestId.empty()&&completed.contains(pendingRequestId))completed.at(pendingRequestId).second=
            {{"ok",false},{"request_id",pendingRequestId},{"state","PLAN_CANCELED_BY_STOP"},
             {"error","pending plan canceled by stop"},{"retry_will_not_execute",true}};
        pendingPlan=nullptr;pendingRequestId.clear();result={{"ok",true},{"accepted",true},{"completion","query status"}};}
    else if(command=="mark"){result={{"ok",true},{"accepted",true},{"checkpoint",runtime->Mark(request.at("label"))}};}
    else throw std::runtime_error("unknown command");
    result["request_id"]=id;
    if(command=="mark")result["generation"]=result.at("checkpoint").at("generation");
    else if(command=="start"||command=="stop")result["generation"]=runtime->Status().at("generation");
    if(mutation)completed.at(id).second=result;return result;
    }catch(const std::exception& e){if(!mutation)throw;Json failure={{"ok",false},{"request_id",id},
            // The control boundary cannot assume every backend exception was
            // raised before its first side effect. Preserve a stable receipt,
            // forbid replay, and require status/manifest attribution.
            {"state","EXECUTION_UNCERTAIN"},{"error",e.what()},{"retry_will_not_execute",true},
            {"query_status_required",true}};
        completed.at(id).second=failure;return failure;}
}
bool Transfer(HANDLE pipe,void* data,DWORD bytes,bool write){
    unsigned char* p=(unsigned char*)data;DWORD done=0;
    while(done<bytes){OVERLAPPED ov{};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!ov.hEvent)return false;
        // Slice large responses so the per-call timeout bounds a bounded amount
        // of data instead of an unbounded status document.
        DWORD slice=(DWORD)std::min<size_t>(bytes-done,256*1024);
        DWORD actual=0;BOOL ok=write?WriteFile(pipe,p+done,slice,&actual,&ov):ReadFile(pipe,p+done,slice,&actual,&ov);
        if(!ok&&GetLastError()==ERROR_IO_PENDING){if(WaitForSingleObject(ov.hEvent,15000)==WAIT_OBJECT_0)ok=GetOverlappedResult(pipe,&ov,&actual,FALSE);
            else{CancelIoEx(pipe,&ov);GetOverlappedResult(pipe,&ov,&actual,TRUE);ok=FALSE;}}
        CloseHandle(ov.hEvent);if(!ok||!actual)return false;done+=actual;}
    return true;
}
uc::Json ServeConnection(HANDLE pipe,const std::function<uc::Json(const uc::Json&)>& handler){
    uint32_t size=0;
    if(!Transfer(pipe,&size,4,false)||!size||size>16*1024*1024)return nullptr;
    std::string input(size,'\0');
    if(!Transfer(pipe,input.data(),size,false))return nullptr;
    uc::Json response,parsed;
    try{parsed=uc::Json::parse(input);response=handler(parsed);}
    catch(const std::exception& e){response={{"ok",false},{"error",e.what()},{"request_id",parsed.is_object()?parsed.value("request_id",uc::Json(nullptr)):uc::Json(nullptr)}};}
    auto output=response.dump();uint32_t length=(uint32_t)output.size();
    if(Transfer(pipe,&length,4,true)&&Transfer(pipe,output.data(),length,true)){
        // Keep the pipe connected until the client has consumed the
        // whole reply. Transfer bounds only this I/O, not capture.
        unsigned char ack=0;Transfer(pipe,&ack,1,false);}
    return response;
}
DWORD WINAPI Control(void*) try {
    PipeSecurity security;wchar_t name[128];swprintf_s(name,L"\\\\.\\pipe\\UnifiedCapture.%lu",GetCurrentProcessId());
    for(;;){HANDLE pipe=CreateControlPipe(name,security);
        if(pipe==INVALID_HANDLE_VALUE)return 1;
        OVERLAPPED ov{};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);BOOL connected=ConnectNamedPipe(pipe,&ov);DWORD error=GetLastError();
        if(!connected&&error==ERROR_IO_PENDING){WaitForSingleObject(ov.hEvent,INFINITE);DWORD ignored=0;connected=GetOverlappedResult(pipe,&ov,&ignored,FALSE);}
        else if(!connected&&error==ERROR_PIPE_CONNECTED)connected=TRUE;
        CloseHandle(ov.hEvent);
        if(connected)ServeConnection(pipe,[](const uc::Json& request){return Handle(request);});
        DisconnectNamedPipe(pipe);CloseHandle(pipe);}
}catch(const std::exception& e){OutputDebugStringA(e.what());return 1;}
// Runtime construction failed (bad output root, storage unavailable...): keep
// the control surface alive so callers learn WHY instead of timing out on a
// missing pipe and blaming the loader.
DWORD WINAPI DegradedControl(void* reasonPtr) try {
    std::string reason=(const char*)reasonPtr;delete[] (char*)reasonPtr;
    PipeSecurity security;wchar_t name[128];swprintf_s(name,L"\\\\.\\pipe\\UnifiedCapture.%lu",GetCurrentProcessId());
    for(;;){HANDLE pipe=CreateControlPipe(name,security);
        if(pipe==INVALID_HANDLE_VALUE)return 1;
        OVERLAPPED ov{};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);BOOL connected=ConnectNamedPipe(pipe,&ov);DWORD error=GetLastError();
        if(!connected&&error==ERROR_IO_PENDING){WaitForSingleObject(ov.hEvent,INFINITE);DWORD ignored=0;connected=GetOverlappedResult(pipe,&ov,&ignored,FALSE);}
        else if(!connected&&error==ERROR_PIPE_CONNECTED)connected=TRUE;
        CloseHandle(ov.hEvent);
        if(connected)ServeConnection(pipe,[&reason](const uc::Json&){return uc::Json{{"ok",false},
            {"state","OBSERVER_WORKER_FAILED"},{"error","observer worker failed to initialize: "+reason}};});
        DisconnectNamedPipe(pipe);CloseHandle(pipe);}
}catch(const std::exception& e){OutputDebugStringA(e.what());return 1;}
}
DWORD WINAPI Bootstrap(void*){
    for(;;){
        {std::lock_guard lock(controlMutex);
        uc::Json plan;std::string requestId;{std::lock_guard pl(pendingMutex);plan=pendingPlan;requestId=pendingRequestId;}
        if(plan.is_null())plan=runtime->RebindPlan();
        if(!plan.is_null()){
            try{
            // Check module presence before expensive source hashing. No waiting timeout.
            bool present=true;for(auto& module:plan.at("modules")){auto image=uc::Utf8(module.at("image").get<std::string>()).wstring();
                if(!GetModuleHandleW(image.c_str()))present=false;}
            if(present){auto compiled=uc::Compile(plan,[](uint64_t at){return runtime->SlotOriginal(at);});auto applied=runtime->Apply(std::move(compiled));
                    if(!requestId.empty()&&completed.contains(requestId)){applied["request_id"]=requestId;completed.at(requestId).second=applied;}
                    std::lock_guard pl(pendingMutex);pendingPlan=nullptr;pendingRequestId.clear();bootstrapError.clear();}
            }catch(const std::exception& e){std::lock_guard pl(pendingMutex);bootstrapError=e.what();
                if(bootstrapError.rfind("WAITING_",0)!=0){
                    if(!requestId.empty()&&completed.contains(requestId))completed.at(requestId).second=
                        {{"ok",false},{"request_id",requestId},{"state","EXECUTION_UNCERTAIN"},{"error",bootstrapError},
                         {"retry_will_not_execute",true},{"query_status_required",true}};
                    pendingPlan=nullptr;pendingRequestId.clear();}}
        }}
        Sleep(250);
    }
}
DWORD WINAPI Worker(void*){
    HMODULE self=nullptr;GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)&Worker,&self);
    try{
        wchar_t module[32768];auto moduleSize=GetModuleFileNameW(self,module,(DWORD)std::size(module));
        uc::Require(moduleSize>0&&moduleSize<std::size(module),"observer module path unavailable or truncated");
        uc::fs::path directory=uc::fs::path(module).parent_path();
        wchar_t output[32768],bootstrap[32768],local[32768];
        auto environment=[](const wchar_t* name,wchar_t* value){auto size=GetEnvironmentVariableW(name,value,32768);
            uc::Require(size<32768,"environment path is too long");return size!=0;};
        uc::fs::path root;
        if(environment(L"UC_OUTPUT_ROOT",output))root=uc::fs::path(output);
        else if(environment(L"LOCALAPPDATA",local))root=uc::fs::path(local)/L"UnifiedCapture"/L"evidence";
        else root=uc::fs::temp_directory_path()/L"UnifiedCapture"/L"evidence";
        runtime=new uc::Runtime(root);
        uc::fs::path selected=environment(L"UC_BOOTSTRAP",bootstrap)?uc::fs::path(bootstrap):directory/L"bootstrap.json";
        try{if(uc::fs::exists(selected)){auto bytes=uc::ReadFile(selected);auto parsedBootstrap=uc::Json::parse(bytes);
            if(parsedBootstrap.value("schema","")=="uc.bootstrap.v1"&&parsedBootstrap.value("mode","")=="control-only"){
                pendingPlan=nullptr;runtime->Meta({{"kind","bootstrap_control_only"},{"file",selected.string()},{"qpc",uc::Clock()}});}
            else if(parsedBootstrap.value("schema","")=="uc.bootstrap.v1"&&parsedBootstrap.value("mode","")=="d3d11-capture"){
                runtime->EnableD3D11Observer(parsedBootstrap.at("d3d11"));pendingPlan=nullptr;
                runtime->Meta({{"kind","bootstrap_d3d11_capture"},{"file",selected.string()},{"qpc",uc::Clock()}});}
            else pendingPlan=std::move(parsedBootstrap);}}
        catch(const std::exception& e){bootstrapError=e.what();pendingPlan=nullptr;
            runtime->Meta({{"kind","bootstrap_error"},{"error",bootstrapError},{"file",selected.string()},{"qpc",uc::Clock()}});}
        HANDLE control=CreateThread(nullptr,0,Control,nullptr,0,nullptr),boot=CreateThread(nullptr,0,Bootstrap,nullptr,0,nullptr);
        if(control)CloseHandle(control);if(boot)CloseHandle(boot);
        for(;;){runtime->Tick();Sleep(1);}
    }catch(const std::exception& e){
        // Keep a control surface alive with the failure reason instead of a
        // missing pipe, so operators can attribute startup failures.
        OutputDebugStringA(e.what());
        char* reason=new(std::nothrow) char[strlen(e.what())+1];if(!reason)return 1;
        strcpy_s(reason,strlen(e.what())+1,e.what());
        HANDLE degraded=CreateThread(nullptr,0,DegradedControl,reason,0,nullptr);
        if(degraded)CloseHandle(degraded);else delete[] reason;
        return 1;}
}
extern "C" __declspec(dllexport) unsigned UnifiedCaptureProtocolVersion(){return 1;}
extern "C" __declspec(dllexport) BOOL UnifiedCaptureD3D11Ready(){return runtime&&runtime->D3D11ObserverReady();}
extern "C" __declspec(dllexport) BOOL UnifiedCaptureD3D11Captured(){return runtime&&runtime->D3D11ObserverCaptured();}
BOOL WINAPI DllMain(HINSTANCE,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){HANDLE thread=CreateThread(nullptr,0,Worker,nullptr,0,nullptr);
    if(!thread)return FALSE;CloseHandle(thread);}return TRUE;}
