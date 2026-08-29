#include "runtime.h"
#include <intrin.h>
#include <type_traits>
namespace uc {
namespace {
Hook* slots[64]{};unsigned used=0;
template<class T> uint64_t Bits(T value){uint64_t result=0;static_assert(sizeof(T)<=8);std::memcpy(&result,&value,sizeof(value));return result;}
template<size_t Index,class...Args> void __fastcall Wrapper(Args... args){
    Hook& h=*slots[Index];h.executing.fetch_add(1);DWORD before=GetLastError();
    Abi abi{};uint64_t values[]={Bits(args)...};std::memcpy(abi.args,values,sizeof(values));abi.argumentMask=(1U<<sizeof...(Args))-1;
    // Stack marker is observer scope bookkeeping, NOT an original CPU register.
    abi.stackMarker=(uint64_t)_AddressOfReturnAddress();
    alignas(Token) unsigned char memory[sizeof(Token)];Token* token=new(memory)Token();
    Runtime::instance->Begin(h,abi,*token);SetLastError(before);
    __try {((void(__fastcall*)(Args...))(uintptr_t)h.original)(args...);}
    __finally {DWORD after=GetLastError();Runtime::instance->End(h,abi,*token,AbnormalTermination()!=FALSE);token->~Token();
        h.executing.fetch_sub(1);SetLastError(after);}
}
template<class...Args,size_t...I> auto Table(std::index_sequence<I...>){return std::array<void*,sizeof...(I)>{(void*)&Wrapper<I,Args...>...};}
template<class...Args> void* Select(unsigned n){static auto table=Table<Args...>(std::make_index_sequence<64>{});return table[n];}
}
void* LegacyWrapper(Hook& h){Require(used<64,"legacy wrapper bank capacity reached (not a snapshot limit)");unsigned n=used++;
    slots[n]=&h;const auto& abi=h.abi;
    if(abi=="void_p")return Select<void*>(n);
    if(abi=="void_pp")return Select<void*,void*>(n);
    if(abi=="state_ptr")return Select<void*,int32_t,int32_t,void*>(n);
    if(abi=="state_id")return Select<int32_t,int32_t,int32_t,void*>(n);
    if(abi=="float_name")return Select<void*,void*,float>(n);
    if(abi=="float_id")return Select<void*,int32_t,float>(n);
    if(abi=="bool_name")return Select<void*,void*,unsigned char>(n);
    if(abi=="bool_id")return Select<void*,int32_t,unsigned char>(n);
    if(abi=="int_name")return Select<void*,void*,int32_t>(n);
    if(abi=="int_id")return Select<void*,int32_t,int32_t>(n);
    if(abi=="trigger_name")return Select<void*,void*>(n);
    if(abi=="trigger_id")return Select<void*,int32_t>(n);
    if(abi=="damp_name")return Select<void*,void*,float,float,float>(n);
    if(abi=="damp_id")return Select<void*,int32_t,float,float,float>(n);
    throw std::runtime_error("unsupported legacy ABI");
}
}
