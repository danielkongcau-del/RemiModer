#include "common.h"
#include <intrin.h>
#include <thread>
#include <iostream>
using uc::Json;
struct State {uint64_t value=10,count=3;unsigned char data[24]{};};
static State fixtureState;
static HANDLE releaseEvent=nullptr,enteredEvent=nullptr;
static std::vector<std::thread> blocked;
static HMODULE dependency=nullptr;
extern "C" uint64_t PairRuntimeTarget(uint64_t*,uint64_t);
extern "C" uint64_t PairRuntimeRecursive(uint64_t*,uint32_t);
extern "C" void PairRuntimeBlock(uint64_t*);
extern "C" void PairRuntimeBlockBody(uint64_t* value){SetEvent(enteredEvent);WaitForSingleObject(releaseEvent,INFINITE);*value+=11;}
extern "C" __declspec(noinline) uint64_t FixtureGum(State* s,uint64_t n){
    _ReadWriteBarrier();__nop();__nop();__nop();__nop();__nop();__nop();__nop();__nop();
    s->value+=n;_ReadWriteBarrier();return s->value;
}
extern "C" __declspec(noinline) void FixtureBlock(State* s){
    SetEvent(enteredEvent);WaitForSingleObject(releaseEvent,INFINITE);s->value+=7;
}
extern "C" __declspec(noinline) void FixtureMutate(void* object,void* input){
    auto* s=(State*)object;s->value+=(uint64_t)input;_ReadWriteBarrier();
}
extern "C" __declspec(noinline) void FixtureFloat(void* object,int32_t id,float value){
    uint32_t bits;std::memcpy(&bits,&value,4);((State*)object)->value=(uint64_t)bits+(uint32_t)id;_ReadWriteBarrier();
}
extern "C" __declspec(noinline) void FixtureState(void* object,int32_t layer,int32_t index,void* output){
    auto p=(uint32_t*)output;for(unsigned i=0;i<10;++i)p[i]=(uint32_t)((State*)object)->value+i+layer+index;}
extern "C" __declspec(noinline) void FixtureRaise(void*){RaiseException(0xe0414243,0,0,nullptr);}
using MutateFn=void(*)(void*,void*);using FloatFn=void(*)(void*,int32_t,float);using StateFn=void(*)(void*,int32_t,int32_t,void*);using RaiseFn=void(*)(void*);
alignas(8) static MutateFn mutate=FixtureMutate;
alignas(8) static FloatFn floating=FixtureFloat;
alignas(8) static StateFn stateSlot=FixtureState;
alignas(8) static RaiseFn raises=FixtureRaise;
static bool TryRaise(){__try{raises(&fixtureState);return false;}__except(GetExceptionCode()==0xe0414243?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){return true;}}
static bool TryGumRaise(){__try{FixtureRaise(&fixtureState);return false;}__except(GetExceptionCode()==0xe0414243?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){return true;}}
extern "C" __declspec(noinline) uint64_t FixtureRecursive(State* s,unsigned depth){
    __nop();__nop();__nop();s->count+=1;
    using Fn=uint64_t(*)(State*,unsigned);static Fn volatile self=FixtureRecursive;
    return depth?self(s,depth-1)+1:s->count;
}
struct Mixed {double number;uint64_t bits;};
extern "C" __declspec(noinline) double FixtureMixed(double x,float y,Mixed m){
    __nop();__nop();__nop();__nop();return x+y+m.number+(double)m.bits;
}
extern "C" __declspec(noinline) void FixtureProbe(State* s){__nop();__nop();__nop();__nop();__nop();s->count+=2;}
int wmain(int argc,wchar_t** argv){
    if(argc!=3){std::cerr<<"FixtureHost <DLL> <output-directory>\n";return 2;}
    SetEnvironmentVariableW(L"UC_OUTPUT_ROOT",argv[2]);wchar_t selected[32768];
    auto selectedSize=GetEnvironmentVariableW(L"UC_FIXTURE_BOOTSTRAP",selected,(DWORD)std::size(selected));
    if(selectedSize>=std::size(selected))return 4;
    SetEnvironmentVariableW(L"UC_BOOTSTRAP",selectedSize?selected:L"uc-fixture-no-bootstrap.json");
    auto dll=LoadLibraryW(argv[1]);if(!dll){std::cerr<<"LoadLibrary failed "<<GetLastError();return 3;}
    auto base=(uint64_t)GetModuleHandleW(nullptr);wchar_t path[32768];auto pathSize=GetModuleFileNameW(nullptr,path,(DWORD)std::size(path));
    if(!pathSize||pathSize>=std::size(path))return 5;
    Json targets=Json::object();auto add=[&](const char* name,void* address,void* target,const char* abi){
        targets[name]={{"rva",(uint64_t)address-base},{"target_rva",(uint64_t)target-base},
            {"expected_prefix",uc::Hex(target,32)},{"abi",abi}};};
    auto findPairExit=[](void* entry){auto* bytes=(unsigned char*)entry;for(size_t i=0;i<128;++i){bool match=true;
        for(size_t n=0;n<15;++n)match&=bytes[i+n]==0x90;if(match&&bytes[i+15]==0xc3)return (void*)(bytes+i);}
        throw std::runtime_error("pair fixture exit marker missing");};
    add("gum",(void*)FixtureGum,(void*)FixtureGum,"");add("block",(void*)FixtureBlock,(void*)FixtureBlock,"");
    add("mutate",&mutate,(void*)FixtureMutate,"void_pp");add("float",&floating,(void*)FixtureFloat,"float_id");
    add("state",&stateSlot,(void*)FixtureState,"state_ptr");add("raise",&raises,(void*)FixtureRaise,"void_p");
    add("gum_raise",(void*)FixtureRaise,(void*)FixtureRaise,"");
    add("recursive",(void*)FixtureRecursive,(void*)FixtureRecursive,"");
    add("mixed",(void*)FixtureMixed,(void*)FixtureMixed,"");add("probe",(void*)FixtureProbe,(void*)FixtureProbe,"");
    add("pair_entry",(void*)PairRuntimeTarget,(void*)PairRuntimeTarget,"");
    add("pair_exit",findPairExit((void*)PairRuntimeTarget),findPairExit((void*)PairRuntimeTarget),"");
    add("pair_recursive_entry",(void*)PairRuntimeRecursive,(void*)PairRuntimeRecursive,"");
    add("pair_recursive_exit",findPairExit((void*)PairRuntimeRecursive),findPairExit((void*)PairRuntimeRecursive),"");
    add("pair_block_entry",(void*)PairRuntimeBlock,(void*)PairRuntimeBlock,"");
    add("pair_block_exit",findPairExit((void*)PairRuntimeBlock),findPairExit((void*)PairRuntimeBlock),"");
    Json info={{"pid",GetCurrentProcessId()},{"module",uc::fs::path(path).filename().string()},{"module_path",uc::fs::path(path).string()},
        {"sha256",uc::FileSha(path)},{"base",base},{"object",(uint64_t)&fixtureState},{"targets",targets}};
    std::cout<<info.dump()<<std::endl;
    releaseEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);enteredEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    std::string line;while(std::getline(std::cin,line)){try{auto cmd=Json::parse(line);auto op=cmd.at("op").get<std::string>();Json result;
        if(op=="gum"){unsigned n=cmd.value("count",1U);for(unsigned i=0;i<n;++i)FixtureGum(&fixtureState,1);result={{"value",fixtureState.value}};}
        else if(op=="mutate"){unsigned n=cmd.value("count",1U);for(unsigned i=0;i<n;++i)mutate(&fixtureState,(void*)1);result={{"value",fixtureState.value}};}
        else if(op=="float"){uint32_t bits=cmd.value("bits",0x7fc01234U);float value;std::memcpy(&value,&bits,4);floating(&fixtureState,2,value);result={{"value",fixtureState.value}};}
        else if(op=="state"){uint32_t output[10];stateSlot(&fixtureState,1,2,output);result={{"words",output}};}
        else if(op=="recursive"){result={{"value",FixtureRecursive(&fixtureState,cmd.value("depth",5U))}};}
        else if(op=="mixed"){result={{"value",FixtureMixed(1.25f,2.5f,{3.5,9})}};}
        else if(op=="probe"){FixtureProbe(&fixtureState);result={{"ok",true}};}
        else if(op=="pair"){result={{"value",PairRuntimeTarget(&fixtureState.value,cmd.value("add",1ULL))}};}
        else if(op=="pair_recursive"){result={{"value",PairRuntimeRecursive(&fixtureState.value,cmd.value("depth",3U))}};}
        else if(op=="pair_block"){ResetEvent(releaseEvent);ResetEvent(enteredEvent);blocked.emplace_back([](){PairRuntimeBlock(&fixtureState.value);});
            WaitForSingleObject(enteredEvent,3000);result={{"blocked",true}};}
        else if(op=="stress"){unsigned count=cmd.value("count",5000U),threads=cmd.value("threads",4U);std::vector<std::thread> workers;
            for(unsigned i=0;i<threads;++i)workers.emplace_back([=](){State local;for(unsigned k=0;k<count;++k)mutate(&local,(void*)1);});
            for(auto& worker:workers)worker.join();result={{"calls",count*threads}};}
        else if(op=="raise")result={{"caught",TryRaise()}};
        else if(op=="gum_raise")result={{"caught",TryGumRaise()}};
        else if(op=="block"){ResetEvent(releaseEvent);ResetEvent(enteredEvent);blocked.emplace_back([](){FixtureBlock(&fixtureState);});
            WaitForSingleObject(enteredEvent,3000);result={{"blocked",true}};}
        else if(op=="release"){SetEvent(releaseEvent);for(auto& worker:blocked)if(worker.joinable())worker.join();blocked.clear();result={{"released",true}};}
        else if(op=="conflict"){mutate=FixtureMutate;result={{"changed",true}};}
        else if(op=="load_dependency"){
            auto dependencyPath=uc::fs::path(argv[1]).parent_path()/L"FixtureModule.dll";dependency=LoadLibraryW(dependencyPath.c_str());
            if(!dependency)throw std::runtime_error("fixture dependency load failed");result={{"base",(uint64_t)dependency}};}
        else if(op=="unload_dependency"){if(dependency){FreeLibrary(dependency);dependency=nullptr;}result={{"unloaded",true}};}
        else if(op=="quit"){SetEvent(releaseEvent);for(auto& worker:blocked)if(worker.joinable())worker.join();blocked.clear();std::cout<<"{\"quit\":true}"<<std::endl;break;}
        else throw std::runtime_error("unknown fixture operation");std::cout<<result.dump()<<std::endl;
    }catch(const std::exception& e){std::cout<<Json({{"error",e.what()}}).dump()<<std::endl;}}
    return 0;
}
