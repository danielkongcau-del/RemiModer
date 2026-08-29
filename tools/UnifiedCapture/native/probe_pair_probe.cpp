#include "common.h"
#pragma warning(push)
#pragma warning(disable:4324)
#include "frida-gum.h"
#pragma warning(pop)
#include <iostream>

extern "C" uint64_t ProbeFaultMemory(void*);
extern "C" uint64_t ProbeFaultCall();
extern "C" uint64_t ProbeEpilogue(uint64_t);
extern "C" unsigned char ProbeEpilogueSite;
extern "C" uint64_t ProbeLongEpilogue(uint64_t);
extern "C" unsigned char ProbeLongEpilogueSite;
extern "C" uint64_t ProbePopEpilogue(uint64_t);
extern "C" unsigned char ProbePopEpilogueSite;
extern "C" uint64_t ProbeRspTarget(uint64_t);
extern "C" uint64_t ProbeRspCaller(uint64_t);
extern "C" uint64_t ExpectedReturn=0;

static constexpr DWORD FixtureCode=0xe0414243;
static std::atomic<uint64_t> hits{0};
static uint64_t observedRsp=0,observedReturn=0;

extern "C" void RaiseFixtureSeh(){RaiseException(FixtureCode,0,0,nullptr);}

static void OnProbe(GumInvocationContext* context,gpointer){
    hits.fetch_add(1);
    if(context&&context->cpu_context){
        observedRsp=context->cpu_context->rsp;
        uc::Read(observedRsp,&observedReturn,sizeof(observedReturn));
    }
}

struct Probe {
    GumInterceptor* interceptor=nullptr;
    GumInvocationListener* listener=nullptr;
    void* target=nullptr;
    uc::Bytes before,after;
    GumAttachReturn status=GUM_ATTACH_WRONG_SIGNATURE;
    explicit Probe(void* address):target(address),before(32),after(32){
        uc::Read((uint64_t)target,before.data(),before.size());
        interceptor=gum_interceptor_obtain();listener=gum_make_probe_listener(OnProbe,nullptr,nullptr);
        GumAttachOptions options{};status=gum_interceptor_attach(interceptor,target,listener,&options);
        uc::Read((uint64_t)target,after.data(),after.size());
    }
    ~Probe(){if(listener){if(status==GUM_ATTACH_OK){gum_interceptor_detach(interceptor,listener);gum_interceptor_flush_listener(interceptor,listener);}
        g_object_unref(listener);}if(interceptor)g_object_unref(interceptor);}
    uc::Json Evidence()const{
        uc::Json changed=uc::Json::array();for(size_t i=0;i<before.size();++i)if(before[i]!=after[i])changed.push_back(i);
        return {{"probe_install_status",(int)status},{"before",uc::Hex(before.data(),before.size())},
            {"after",uc::Hex(after.data(),after.size())},{"changed_byte_offsets",changed}};
    }
};

static bool CatchMemory(){
    __try{ProbeFaultMemory((void*)1);return false;}
    __except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){return true;}
}
static bool CatchCall(){
    __try{ProbeFaultCall();return false;}
    __except(GetExceptionCode()==FixtureCode?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){return true;}
}

int main(int argc,char** argv){
    if(argc!=2)return 2;SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);gum_init_embedded();
    std::string mode=argv[1];uc::Json result={{"schema","uc.probe-pair-fixture.v1"},{"mode",mode},{"pid",GetCurrentProcessId()}};
    if(mode=="baseline-fault-memory")result["caught"]=CatchMemory();
    else if(mode=="probe-fault-memory"){
        Probe probe((void*)ProbeFaultMemory);result["probe"]=probe.Evidence();result["caught"]=CatchMemory();result["hits"]=hits.load();}
    else if(mode=="baseline-fault-call")result["caught"]=CatchCall();
    else if(mode=="probe-fault-call"){
        Probe probe((void*)ProbeFaultCall);result["probe"]=probe.Evidence();result["caught"]=CatchCall();result["hits"]=hits.load();}
    else if(mode=="probe-epilogue"){
        Probe probe((void*)&ProbeEpilogueSite);result["probe"]=probe.Evidence();auto value=ProbeEpilogue(0x1122334455667788ULL);
        result["value"]=value;result["preserved"]=value==0x1122334455667788ULL;result["hits"]=hits.load();}
    else if(mode=="probe-long-epilogue"){
        Probe probe((void*)&ProbeLongEpilogueSite);result["probe"]=probe.Evidence();auto value=ProbeLongEpilogue(0x8877665544332211ULL);
        result["value"]=value;result["preserved"]=value==0x8877665544332211ULL;result["hits"]=hits.load();}
    else if(mode=="probe-pop-epilogue"){
        Probe probe((void*)&ProbePopEpilogueSite);result["probe"]=probe.Evidence();auto value=ProbePopEpilogue(0x1020304050607080ULL);
        result["value"]=value;result["preserved"]=value==0x1020304050607080ULL;result["hits"]=hits.load();}
    else if(mode=="probe-rsp"){
        Probe probe((void*)ProbeRspTarget);result["probe"]=probe.Evidence();auto value=ProbeRspCaller(0x55aa);
        result["value"]=value;result["hits"]=hits.load();result["observed_rsp"]=observedRsp;
        result["observed_return_address"]=observedReturn;result["expected_return_address"]=ExpectedReturn;
        result["architectural_rsp_proven"]=observedReturn==ExpectedReturn&&observedReturn!=0;}
    else return 3;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    result["cfg_policy_query"]=GetProcessMitigationPolicy(GetCurrentProcess(),ProcessControlFlowGuardPolicy,&cfg,sizeof(cfg))!=FALSE;
    result["cfg_enabled"]=cfg.EnableControlFlowGuard!=0;
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
    result["cet_user_shadow_stack_policy_query"]=GetProcessMitigationPolicy(
        GetCurrentProcess(),ProcessUserShadowStackPolicy,&cet,sizeof(cet))!=FALSE;
    result["cet_user_shadow_stack_enabled"]=cet.EnableUserShadowStack!=0;
    result["cet_user_shadow_stack_strict_mode"]=cet.EnableUserShadowStackStrictMode!=0;
    std::cout<<result.dump()<<std::endl;return 0;
}
