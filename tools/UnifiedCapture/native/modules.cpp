#include "modules.h"
namespace uc {
namespace {
struct Unicode {USHORT length,maximum;PWSTR buffer;};
struct Notification {ULONG flags;const Unicode* full;const Unicode* name;PVOID base;ULONG size;};
struct Epoch {std::atomic<uint64_t> base{0},epoch{0};std::atomic<bool> loaded{false};};
Epoch epochs[2048];std::atomic<uint64_t> serial{1},overflow{0};bool installed=false;PVOID cookie=nullptr;
uint32_t Find(uint64_t base) noexcept {
    for(uint32_t i=0;i<std::size(epochs);++i){auto current=epochs[i].base.load();if(current==base)return i;
        if(!current){if(epochs[i].base.compare_exchange_strong(current,base)||current==base)return i;}}
    overflow.fetch_add(1);return UINT32_MAX;
}
// Under loader lock: no other-module calls, allocations, locks or JSON. The
// callback records lifecycle epochs, not guessed wall-clock/QPC timestamps.
void CALLBACK Notify(ULONG reason,const Notification* data,PVOID){
    if(reason!=1&&reason!=2)return;auto index=Find((uint64_t)data->base);if(index==UINT32_MAX)return;
    auto& item=epochs[index];item.loaded.store(reason==1);item.epoch.store(serial.fetch_add(1));
}
}
void InitializeModuleNotifications(){if(installed)return;
    using Register=LONG(NTAPI*)(ULONG,decltype(&Notify),PVOID,PVOID*);
    auto fn=(Register)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"LdrRegisterDllNotification");
    Require(fn&&fn(0,Notify,nullptr,&cookie)>=0,"DLL lifecycle notification registration failed");installed=true;}
std::pair<uint32_t,uint64_t> ObserveModule(uint64_t base){
    Require(installed&&overflow.load()==0,"module notification coverage unavailable");
    auto index=Find(base);Require(index!=UINT32_MAX,"module epoch table exhausted");auto& item=epochs[index];
    // For modules already present before our DLL: observe a starting boundary,
    // not a claim that their creation was recorded. Caller holds a loader ref.
    if(!item.epoch.load()){item.loaded.store(true);item.epoch.store(serial.fetch_add(1));}
    Require(item.loaded.load(),"module unloaded during preparation");return {index,item.epoch.load()};
}
bool ModuleStillLoaded(const Module& m) noexcept {if(overflow.load()||m.epochSlot>=std::size(epochs))return false;
    auto& item=epochs[m.epochSlot];return item.base.load()==m.base&&item.loaded.load()&&item.epoch.load()==m.epoch;}
Json ModuleNotificationStatus(){return {{"registered",installed},{"epoch_table_capacity",std::size(epochs)},
    {"overflow",overflow.load()},{"current_epoch_serial",serial.load()},{"notification_qpc_captured",false}};}
}
