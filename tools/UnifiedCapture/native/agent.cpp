#include "runtime.h"
#include <thread>
#include <future>

namespace {
uc::Runtime* runtime=nullptr;
std::mutex controlMutex;
std::unordered_map<std::string,std::pair<std::string,uc::Json>> completed;
std::string bootstrapError;
uc::Json pendingPlan;
std::string pendingRequestId;
std::mutex pendingMutex;

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
    if(command=="capabilities")result={{"ok",true},{"capabilities",runtime->Capabilities()}};
    else if(command=="status"){result=runtime->Status();std::lock_guard pl(pendingMutex);result["bootstrap_error"]=bootstrapError;result["waiting_plan"]=!pendingPlan.is_null();}
    else if(command=="validate"){
        auto compiled=Compile(request.at("plan"),[](uint64_t at){return runtime->SlotOriginal(at);});
        result={{"ok",true},{"plan_hash",compiled->planHash},{"bindings",compiled->bindings},{"activated",false}};
    }
    else if(command=="apply"){
        const auto& plan=request.at("plan");
        try{auto compiled=Compile(plan,[](uint64_t at){return runtime->SlotOriginal(at);});result=runtime->Apply(std::move(compiled));std::lock_guard pl(pendingMutex);pendingPlan=nullptr;pendingRequestId.clear();bootstrapError.clear();}
        catch(const std::exception& e){auto error=std::string(e.what());if(error.rfind("WAITING_",0)!=0)throw;
            std::lock_guard pl(pendingMutex);pendingPlan=plan;pendingRequestId=id;bootstrapError=e.what();result={{"ok",true},{"state",error.substr(0,error.find(':'))}};}
    }else if(command=="start"){runtime->Start();result={{"ok",true},{"accepted",true}};}
    else if(command=="qualify-sites")result=runtime->QualifySites(request.at("qualification"));
    else if(command=="stop"){runtime->Stop();std::lock_guard pl(pendingMutex);pendingPlan=nullptr;pendingRequestId.clear();result={{"ok",true},{"accepted",true},{"completion","query status"}};}
    else if(command=="mark"){runtime->Mark(request.at("label"));result={{"ok",true},{"accepted",true}};}
    else throw std::runtime_error("unknown command");
    result["request_id"]=id;
    if(command=="start"||command=="stop"||command=="mark")result["generation"]=runtime->Status().at("generation");
    if(mutation)completed.at(id).second=result;return result;
}
bool Transfer(HANDLE pipe,void* data,DWORD bytes,bool write){
    unsigned char* p=(unsigned char*)data;DWORD done=0;
    while(done<bytes){OVERLAPPED ov{};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!ov.hEvent)return false;
        DWORD actual=0;BOOL ok=write?WriteFile(pipe,p+done,bytes-done,&actual,&ov):ReadFile(pipe,p+done,bytes-done,&actual,&ov);
        if(!ok&&GetLastError()==ERROR_IO_PENDING){if(WaitForSingleObject(ov.hEvent,5000)==WAIT_OBJECT_0)ok=GetOverlappedResult(pipe,&ov,&actual,FALSE);
            else{CancelIoEx(pipe,&ov);GetOverlappedResult(pipe,&ov,&actual,TRUE);ok=FALSE;}}
        CloseHandle(ov.hEvent);if(!ok||!actual)return false;done+=actual;}
    return true;
}
DWORD WINAPI Control(void*){
    wchar_t name[128];swprintf_s(name,L"\\\\.\\pipe\\UnifiedCapture.%lu",GetCurrentProcessId());
    for(;;){HANDLE pipe=CreateNamedPipeW(name,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,nullptr);
        if(pipe==INVALID_HANDLE_VALUE)return 1;
        OVERLAPPED ov{};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);BOOL connected=ConnectNamedPipe(pipe,&ov);DWORD error=GetLastError();
        if(!connected&&error==ERROR_IO_PENDING){WaitForSingleObject(ov.hEvent,INFINITE);DWORD ignored=0;connected=GetOverlappedResult(pipe,&ov,&ignored,FALSE);}
        else if(!connected&&error==ERROR_PIPE_CONNECTED)connected=TRUE;
        CloseHandle(ov.hEvent);
        if(connected){uint32_t size=0;if(Transfer(pipe,&size,4,false)&&size&&size<=16*1024*1024){
            std::string input(size,'\0');if(Transfer(pipe,input.data(),size,false)){
                uc::Json response,parsed;try{parsed=uc::Json::parse(input);response=Handle(parsed);}
                catch(const std::exception& e){response={{"ok",false},{"error",e.what()},{"request_id",parsed.is_object()?parsed.value("request_id",uc::Json(nullptr)):uc::Json(nullptr)}};}
                auto output=response.dump();uint32_t length=(uint32_t)output.size();
                if(Transfer(pipe,&length,4,true)&&Transfer(pipe,output.data(),length,true)){
                    // Keep the pipe connected until the client has consumed the
                    // whole reply. Transfer bounds only this I/O, not capture.
                    unsigned char ack=0;Transfer(pipe,&ack,1,false);
                }
            }}}
        DisconnectNamedPipe(pipe);CloseHandle(pipe);
    }
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
                        {{"ok",false},{"request_id",requestId},{"state","PREPARATION_FAILED"},{"error",bootstrapError}};
                    pendingPlan=nullptr;pendingRequestId.clear();}}
        }}
        Sleep(250);
    }
}
DWORD WINAPI Worker(void*){
    HMODULE self=nullptr;GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)&Worker,&self);
    try{
        wchar_t module[32768];GetModuleFileNameW(self,module,32768);uc::fs::path directory=uc::fs::path(module).parent_path();
        wchar_t output[32768],bootstrap[32768],local[32768];
        uc::fs::path root;
        if(GetEnvironmentVariableW(L"UC_OUTPUT_ROOT",output,32768))root=uc::fs::path(output);
        else if(GetEnvironmentVariableW(L"LOCALAPPDATA",local,32768))root=uc::fs::path(local)/L"UnifiedCapture"/L"evidence";
        else root=uc::fs::temp_directory_path()/L"UnifiedCapture"/L"evidence";
        runtime=new uc::Runtime(root);
        uc::fs::path selected=GetEnvironmentVariableW(L"UC_BOOTSTRAP",bootstrap,32768)?uc::fs::path(bootstrap):directory/L"bootstrap.json";
        try{if(uc::fs::exists(selected)){auto bytes=uc::ReadFile(selected);auto parsedBootstrap=uc::Json::parse(bytes);
            if(parsedBootstrap.value("schema","")=="uc.bootstrap.v1"&&parsedBootstrap.value("mode","")=="control-only"){
                pendingPlan=nullptr;runtime->Meta({{"kind","bootstrap_control_only"},{"file",selected.string()},{"qpc",uc::Clock()}});}
            else pendingPlan=std::move(parsedBootstrap);}}
        catch(const std::exception& e){bootstrapError=e.what();pendingPlan=nullptr;
            runtime->Meta({{"kind","bootstrap_error"},{"error",bootstrapError},{"file",selected.string()},{"qpc",uc::Clock()}});}
        HANDLE control=CreateThread(nullptr,0,Control,nullptr,0,nullptr),boot=CreateThread(nullptr,0,Bootstrap,nullptr,0,nullptr);
        if(control)CloseHandle(control);if(boot)CloseHandle(boot);
        for(;;){runtime->Tick();Sleep(1);}
    }catch(const std::exception& e){OutputDebugStringA(e.what());return 1;}
}
}
extern "C" __declspec(dllexport) unsigned UnifiedCaptureProtocolVersion(){return 1;}
BOOL WINAPI DllMain(HINSTANCE,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){HANDLE thread=CreateThread(nullptr,0,Worker,nullptr,0,nullptr);
    if(!thread)return FALSE;CloseHandle(thread);}return TRUE;}
