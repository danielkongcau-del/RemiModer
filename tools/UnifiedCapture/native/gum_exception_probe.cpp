// Standalone upstream-capability test. Does not load UnifiedCapture or a game.
#include <windows.h>
#include <cstdio>
#include <cstring>
#pragma warning(push)
#pragma warning(disable:4324)
#include "frida-gum.h"
#pragma warning(pop)
static LONG entered=0,left=0;
static void OnEntry(GumInvocationContext*,gpointer){InterlockedIncrement(&entered);}
static void OnExit(GumInvocationContext*,gpointer){InterlockedIncrement(&left);}
__declspec(noinline) static void RaiseSeh(){RaiseException(0xe0414243,0,0,nullptr);}
__declspec(noinline) static void RaiseCpp(){throw 12345;}
__declspec(noinline) static bool CatchSeh(){
    __try{RaiseSeh();return false;}
    __except(GetExceptionCode()==0xe0414243?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){return true;}
}
__declspec(noinline) static bool CatchCpp(){
    using ThrowFn=void(*)();static ThrowFn volatile target=RaiseCpp;
    try{target();return false;}catch(int n){return n==12345;}
}
int main(int argc,char** argv){
    if(argc!=3)return 2;
    const bool seh=std::strcmp(argv[2],"seh")==0;
    gum_init_embedded();auto* interceptor=gum_interceptor_obtain();
    GumInvocationListener* listener=nullptr;
    if(std::strcmp(argv[1],"baseline")!=0){
        if(std::strcmp(argv[1],"attach")==0)listener=gum_make_call_listener(OnEntry,OnExit,nullptr,nullptr);
        else if(std::strcmp(argv[1],"probe")==0)listener=gum_make_probe_listener(OnEntry,nullptr,nullptr);
        else return 3;
        GumAttachOptions options{};
        auto result=gum_interceptor_attach(interceptor,seh?(void*)RaiseSeh:(void*)RaiseCpp,listener,&options);
        if(result!=GUM_ATTACH_OK){std::printf("{\"attach_error\":%d}\n",result);return 4;}
    }
    std::printf("{\"phase\":\"before_exception\",\"mode\":\"%s\",\"exception\":\"%s\"}\n",argv[1],argv[2]);
    std::fflush(stdout);
    const bool caught=seh?CatchSeh():CatchCpp();
    std::printf("{\"caught\":%s,\"entries\":%ld,\"leaves\":%ld}\n",caught?"true":"false",entered,left);
    std::fflush(stdout);
    if(listener){gum_interceptor_detach(interceptor,listener);
        if(!gum_interceptor_flush_listener(interceptor,listener))return 5;g_object_unref(listener);}
    g_object_unref(interceptor);gum_deinit_embedded();return caught?0:6;
}
