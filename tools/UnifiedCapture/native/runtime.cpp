#include "runtime.h"
#include "readers.h"
#include "modules.h"
#include "pairing.h"
#include <algorithm>
namespace uc {
Runtime* Runtime::instance=nullptr;
namespace {
struct Nest {uint64_t id,sp;};
// This bounds only the ancestry annotation, never events or invocation lifetime.
struct Nesting {std::array<Nest,256> rows{};unsigned count=0;};
thread_local Nesting nesting;
struct PairPayload {uint64_t invocation=0;std::shared_ptr<const Generation> generation;Point* point=nullptr;Cell* cell=nullptr;
    std::array<Hook*,8> exitHooks{};uint32_t exitHookCount=0;};
struct PairState {
    PairLedger ledger{256};std::array<PairPayload,256> payloads{};std::array<PairFrame,256> extracted{};
    PairPayload* Reserve(uint64_t invocation){for(auto& row:payloads)if(!row.invocation){row.invocation=invocation;return &row;}return nullptr;}
    PairPayload* Find(uint64_t invocation){for(auto& row:payloads)if(row.invocation==invocation)return &row;return nullptr;}
    void Release(PairPayload& row){row.generation.reset();row.point=nullptr;row.cell=nullptr;row.exitHookCount=0;row.invocation=0;}
    ~PairState(){for(auto& row:payloads)if(row.invocation){for(uint32_t i=0;i<row.exitHookCount;++i)row.exitHooks[i]->executing.fetch_sub(1);
        if(!row.generation->reclaimed.load()){if(row.cell)row.cell->flags.fetch_or(8|16,std::memory_order_release);
            row.point->loss.Note(Clock(),1,0,true,LossReason::FrameTerminationUnknown);
            row.point->inFlight.fetch_sub(1);const_cast<Generation*>(row.generation.get())->inFlight.fetch_sub(1);}
        row.invocation=0;}}
};
thread_local PairState pairs;
void Parent(uint64_t id,uint64_t sp,uint64_t& parent,bool& known,bool push){
    while(nesting.count&&sp&&sp>=nesting.rows[nesting.count-1].sp)--nesting.count;
    known=nesting.count< nesting.rows.size()&&sp!=0;
    parent=known&&nesting.count?nesting.rows[nesting.count-1].id:0;
    if(push&&known)nesting.rows[nesting.count++]={id,sp};
}
void Pop(uint64_t id){for(unsigned i=nesting.count;i>0;--i)if(nesting.rows[i-1].id==id){nesting.count=i-1;break;}}
void OnProbe(GumInvocationContext* ic,gpointer data){auto& h=*(Hook*)data;Runtime::instance->Probe(h,GumAbi(ic));}
struct SwapResult {bool changed=false,protectionRestored=true;};
SwapResult Swap(uint64_t address,void* expected,void* value){DWORD old=0;
    if(!VirtualProtect((void*)address,8,PAGE_READWRITE,&old))return {};
    SwapResult result;result.changed=InterlockedCompareExchangePointer((void*volatile*)address,value,expected)==expected;DWORD ignored=0;
    result.protectionRestored=VirtualProtect((void*)address,8,old,&ignored)!=0;return result;
}
struct ModuleRef {
    HMODULE value=nullptr;
    explicit ModuleRef(HMODULE handle=nullptr) noexcept:value(handle){}
    ModuleRef(const ModuleRef&)=delete;ModuleRef& operator=(const ModuleRef&)=delete;
    ModuleRef(ModuleRef&& other) noexcept:value(other.value){other.value=nullptr;}
    ModuleRef& operator=(ModuleRef&& other) noexcept {if(this!=&other){if(value)FreeLibrary(value);value=other.value;other.value=nullptr;}return *this;}
    ~ModuleRef(){if(value)FreeLibrary(value);}
};
bool ModulesLive(const Generation& generation) noexcept;
}
Abi GumAbi(GumInvocationContext* ic){Abi a;auto* c=ic->cpu_context;if(!c)return a;
    uint64_t values[]={c->rax,c->rbx,c->rcx,c->rdx,c->rsi,c->rdi,c->rbp,c->rsp,c->r8,c->r9,c->r10,c->r11,c->r12,c->r13,c->r14,c->r15,c->rip};
    std::memcpy(a.regs,values,sizeof(values));a.registerMask=(1U<<RegCount)-1;a.stackMarker=c->rsp;
    // Snapshot the backend context before selecting a logical generation.
    // Individual points may suppress XMM in Capture(), but a global plan flag
    // must never make a late exit use another generation's ABI policy.
    if(c->xmm&&Read((uint64_t)c->xmm,a.xmm,sizeof(a.xmm)))a.xmmMask=0xffff;
    // No inferred arg[]: raw-only hooks stay raw-only even if Ghidra has a prototype.
    return a;}
Runtime::Runtime(fs::path root):outputRoot(std::move(root)){
    Require(instance==nullptr,"one runtime per DLL");store=std::make_unique<Store>(outputRoot);
    HMODULE self=nullptr;wchar_t path[32768];
    Require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&GumAbi,&self),"observer module identity");auto pathSize=GetModuleFileNameW(self,path,(DWORD)std::size(path));
    Require(pathSize>0&&pathSize<std::size(path),"observer module path unavailable or truncated");
    observerPath=fs::path(path).string();observerSha=FileSha(path);
    InitializeModuleNotifications();gum_init_embedded();interceptor=gum_interceptor_obtain();instance=this;flushQpc=Clock();lastModuleCheck=Clock();
    Meta({{"kind","capabilities"},{"value",Capabilities()}});
}
Json Runtime::Capabilities()const{return {{"schema","uc.capabilities.v1"},{"architecture","windows-x64"},{"gum_version","17.17.0"},
    {"observer_file",observerPath},{"observer_sha256",observerSha},
    {"backends",{"slot","gum_probe","gum_function_probe_pair"}},
    {"reads",{"scalar","relative","block","array","string"}},
    {"read_predicates",{"eq","neq"}},{"predicate_phase","enter"},
    {"plan_resource_capture_xmm",true},{"admission_window_accounting",true},{"forced_stop",true},
    {"probe_pair_tls_frame_capacity",256},{"storage_backpressure","nonblocking-bounded-loss-accounted"},
    {"gum_raw_registers",RegNames},{"gum_xmm_registers",16},{"legacy_raw_registers",0},
    {"legacy_abi_values",true},{"legacy_targets_per_process",64},{"ancestry_annotation_depth",256},
    {"automatic_stop",false},{"cumulative_snapshot_limit",nullptr},{"game_runtime_verified",false},
    {"exception_capability",{{"slot_seh","passed-own-fixture"},{"gum_probe_seh_cpp","passed-own-fixture"},
        {"gum_probe_relocated_memory_fault","passed-own-fixture"},{"gum_probe_relocated_call_seh","passed-own-fixture"},
        {"gum_probe_pure_epilogue_return","passed-own-fixture"},{"gum_probe_architectural_rsp","passed-own-fixture"},
        {"gum_function_probe_pair","passed-own-fixture-recursion-sharing-generation-switch"},
        {"cfg_cet_policy_query","passed-own-fixture-target-runtime-check-required"},
        {"evidence","tests/native_robustness.py; tests/probe_pair_matrix.py; standalone Gum 17.17.0, Windows x64"},
        {"arbitrary_exception_safety",false}}},
    {"hook_replace",false},{"mutate_arguments",false},{"module_unload_notification",true},{"module_notifications",ModuleNotificationStatus()},
    {"unloaded_hook_cleanup_guaranteed",false},{"frozen_readers",LegacyCapabilities()}};}
void Runtime::Meta(Json j){std::lock_guard lock(metaMutex);metadata.push_back(std::move(j));}
Bytes Runtime::OriginalPrefix(uint64_t address,size_t size)const{
    Bytes bytes(size);Require(Read(address,bytes.data(),size),"target prefix unreadable");
    for(const auto& h:hooks)if(h->owned&&h->backend!=Backend::Slot)for(auto i:h->patchOffsets){
        uint64_t at=h->target+i;if(at>=address&&at-address<size)bytes[(size_t)(at-address)]=h->sourcePrefix[i];}
    return bytes;
}
Bytes Runtime::ExpectedPrefix(const Hook& hook)const{
    if(hook.backend==Backend::Slot)return hook.installed;
    Bytes result=hook.sourcePrefix;
    for(const auto& h:hooks)if(h->owned&&h->backend!=Backend::Slot)for(auto i:h->patchOffsets){
        uint64_t at=h->target+i;if(at>=hook.target&&at-hook.target<result.size())result[(size_t)(at-hook.target)]=h->installed[i];}
    return result;
}
void Runtime::Install(Hook& h,const Point& p){
    if(h.listener){Require(h.detached&&gum_interceptor_flush_listener(interceptor,h.listener),"previous Gum listener references pending");
        g_object_unref(h.listener);h.listener=nullptr;}
    h.sourcePrefix=OriginalPrefix(p.original,p.prefix.size());Require(h.sourcePrefix==p.prefix,"native instruction prefix mismatch");
    h.before.resize(p.prefix.size());Require(Read(p.original,h.before.data(),h.before.size()),"install target unreadable");h.current=h.before;
    if(p.backend==Backend::Slot){h.reservedSpan=8;h.patchSpan=8;uint64_t original=0;Require(Read(h.target,&original,8),"slot unreadable");
        if(!original)throw std::runtime_error("WAITING_TARGET:"+p.id);Require(original==h.original,"slot already owned or changed");
        if(!h.wrapper)h.wrapper=LegacyWrapper(h);h.installed.resize(8);std::memcpy(h.installed.data(),&h.wrapper,8);
        const auto swap=Swap(h.target,(void*)h.original,h.wrapper);h.owned=swap.changed;
        if(!swap.protectionRestored){h.conflict=true;h.error="slot page protection restore failed";}
        Require(swap.changed,"slot compare exchange conflict");Require(swap.protectionRestored,"slot page protection restore failed");
    }else{
        // Backend-build capability, not a CapturePlan schema constant. The
        // pinned Gum 17.17.0 x64 backend uses at most a 16-byte redirect.
        h.reservedSpan=16;Require(p.prefix.size()>=h.reservedSpan,"Gum physical site needs 16 verified source bytes");
        h.listener=gum_make_probe_listener(OnProbe,&h,nullptr);
        Require(h.listener!=nullptr,"Gum probe listener allocation");GumAttachOptions options{};
        auto result=gum_interceptor_attach(interceptor,(void*)h.target,h.listener,&options);
        if(result!=GUM_ATTACH_OK){g_object_unref(h.listener);h.listener=nullptr;throw std::runtime_error("Gum probe listener installation failed:"+std::to_string(result));}
        h.owned=true;h.installed.resize(p.prefix.size());Require(Read(h.target,h.installed.data(),h.installed.size()),"installed bytes unreadable");
        h.patchOffsets.clear();for(size_t i=0;i<h.installed.size();++i)if(h.before[i]!=h.installed[i])h.patchOffsets.push_back(i);
        Require(!h.patchOffsets.empty(),"Gum install produced no observable redirect");
        if(h.installed[0]==0xe9)h.patchSpan=5;
        else {h.patchSpan=std::max<size_t>(16,h.patchOffsets.back()+1);Require(h.patchSpan<=h.reservedSpan,"unknown Gum redirect span");}
    }
    h.detached=false;h.conflict=false;
    Meta({{"kind","hook_install"},{"hook_id",h.id},{"point",p.id},{"target",h.target},{"backend",p.backend==Backend::Slot?"slot":"gum_probe"},
          {"before_bytes",Hex(h.before.data(),h.before.size())},{"installed_state",Hex(h.installed.data(),h.installed.size())},
          {"unhooked_source_prefix",Hex(h.sourcePrefix.data(),h.sourcePrefix.size())},{"own_changed_byte_offsets",h.patchOffsets},
          {"backend_build_hash","23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475"},
          {"reserved_span",h.reservedSpan},{"required_redirect_span",h.patchSpan},
          {"install_generation",h.installGeneration},{"qpc",Clock()}});
}
void Runtime::Detach(Hook& h){if(!h.owned||h.conflict)return;
    h.current.resize(h.installed.size());if(!Read(h.target,h.current.data(),h.current.size())||h.current!=ExpectedPrefix(h)){h.conflict=true;
        Meta({{"kind","hook_conflict"},{"hook_id",h.id},{"qpc",Clock()},{"current_state",Hex(h.current.data(),h.current.size())}});return;}
    if(h.backend==Backend::Slot){const auto swap=Swap(h.target,h.wrapper,(void*)h.original);
        if(swap.changed)h.owned=false;
        if(!swap.changed||!swap.protectionRestored){h.conflict=true;h.error=!swap.changed?"slot compare exchange conflict":"slot protection restore failed";
            Meta({{"kind","hook_conflict"},{"hook_id",h.id},{"qpc",Clock()},{"error",h.error}});return;}}
    else gum_interceptor_detach(interceptor,h.listener);
    h.owned=false;h.detached=true;Meta({{"kind","hook_detach"},{"hook_id",h.id},{"qpc",Clock()}});
}
Json Runtime::Apply(std::shared_ptr<Generation> gen){std::lock_guard lock(stateMutex);
    if(clean){Require(!forcedTerminal,"forced session is terminal; restart the observed process before another activation");NewSession();}
    Require(!stopRequested.load(),"drain in progress; cannot activate a new plan");
    {std::lock_guard errorLock(errorMutex);Require(storageError.empty(),"storage failed; stop and restart the observed process");}
    Require(!store->SealFailed(),"storage failed; stop and restart the observed process");
    // Hold loader references across verification, patching and publication.
    // Epoch checks alone detect unloads but cannot prevent the mapping from
    // disappearing while the hook backend is reading/writing its code.
    std::vector<ModuleRef> moduleRefs;moduleRefs.reserve(gen->modules.size());
    for(const auto& m:gen->modules){HMODULE handle=nullptr;
        Require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)m.base,&handle)!=FALSE&&
            (uint64_t)handle==m.base,"module load instance changed after preparation");
        moduleRefs.emplace_back(handle);}
    gen->moduleVerifiedEpoch.store(0,std::memory_order_release);
    Require(ModulesLive(*gen),"module load instance changed after preparation");
    // Slot replacement has a separate indirect-dispatch constraint. Code
    // observation uses instruction probes only; the retired call-listener
    // backend has no activation or risk-acceptance path.
    {bool usesSlot=false;for(const auto& p:gen->points)usesSlot|=p->backend==Backend::Slot;
    if(usesSlot){PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
        Require(GetProcessMitigationPolicy(GetCurrentProcess(),ProcessControlFlowGuardPolicy,&cfg,sizeof(cfg))!=FALSE,"target CFG policy query failed");
        if(cfg.EnableControlFlowGuard)Require(gen->source.value("accept_cfg_indirect_dispatch_risk",Json(false)).get<bool>(),
            "target enables CFG: slot replacement makes indirect dispatch through the wrapper an invalid call target "
            "(process termination); set accept_cfg_indirect_dispatch_risk=true to own that risk");}}
    if(gen->source.at("schema")=="uc.capture-plan.v2"){PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
        Require(GetProcessMitigationPolicy(GetCurrentProcess(),ProcessControlFlowGuardPolicy,&cfg,sizeof(cfg))!=FALSE,"target CFG policy query failed");
        Require(GetProcessMitigationPolicy(GetCurrentProcess(),ProcessUserShadowStackPolicy,&cet,sizeof(cet))!=FALSE,"target CET policy query failed");
        Meta({{"kind","target_process_mitigation"},{"qpc",Clock()},{"generation_preparing",generationCounter+1},
            {"cfg_enabled",cfg.EnableControlFlowGuard!=0},{"cet_user_shadow_stack_enabled",cet.EnableUserShadowStack!=0},
            {"cet_user_shadow_stack_strict",cet.EnableUserShadowStackStrictMode!=0},{"game_runtime_verified",false}});}
    for(auto& old:hooks)if(old->owned){Bytes current(old->installed.size());
        if(!Read(old->target,current.data(),current.size())||current!=ExpectedPrefix(*old)){
            old->conflict=true;old->error="existing owned state changed before preparation";throw std::runtime_error(old->error);}}
    uint64_t next=generationCounter+1;std::vector<Hook*> added;bool generationStaged=false;
    try{
        auto ensure=[&](uint64_t address,uint64_t original,Backend backend,const std::string& abi,const Bytes& prefix,const std::string& label){
            Hook* h=nullptr;for(auto& old:hooks)if(old->target==address){h=old.get();break;}
            if(!h){const size_t reserve=backend==Backend::Slot?8:16;
                for(const auto& old:hooks)if(old->owned){const size_t oldReserve=old->reservedSpan?old->reservedSpan:(old->backend==Backend::Slot?8:16);
                    const uint64_t oldEnd=Add(old->target,oldReserve),newEnd=Add(address,reserve);
                    Require(oldEnd<=address||newEnd<=old->target,"partial physical hook reservation overlap");}
                auto created=std::make_unique<Hook>();h=created.get();h->id=(uint32_t)hooks.size();h->target=address;h->original=original;
                h->backend=backend;h->abi=abi;hooks.push_back(std::move(created));}
            Require(h->backend==backend&&h->abi==abi&&h->original==original,"existing hook has a different mechanism/ABI");
            Require(!h->conflict,"hook ownership conflict");
            if(!h->owned){Point site;site.id=label;site.address=address;site.original=original;site.backend=backend;site.abi=abi;site.prefix=prefix;
                h->installGeneration=next;added.push_back(h);Install(*h,site);}
            else {Require(h->sourcePrefix==prefix,"owned hook source prefix changed");Bytes current(h->installed.size());
                Require(Read(h->target,current.data(),current.size())&&current==ExpectedPrefix(*h),"owned hook was modified");}
            return h;
        };
        for(auto& p:gen->points){auto* entry=ensure(p->address,p->original,p->backend,p->abi,p->prefix,p->id);p->hookId=entry->id;
            if(p->requiredRedirectSpan)Require(entry->patchSpan==p->requiredRedirectSpan,"entry redirect differs from compiled patch contract");
            for(auto& exit:p->exits){auto* hook=ensure(exit.address,exit.address,Backend::GumProbe,"",exit.prefix,p->id+"/"+exit.id);exit.hookId=hook->id;exit.runtimeHook=hook;
                Require(hook->patchSpan==exit.requiredRedirectSpan,"exit redirect differs from compiled patch contract");}
        }
        // Complete every allocation and every fallible durable write before
        // publishing the new shared_ptr.  If any step below fails, callbacks
        // still see the previous immutable generation and installed additions
        // are detached by the rollback path.
        gen->generation=next;gen->byHook.resize(hooks.size());for(auto& p:gen->points){gen->byHook[p->hookId].push_back(p);
            for(auto& exit:p->exits)gen->byHook[exit.hookId].push_back(p);}
        Require(ModulesLive(*gen),"module load instance changed during hook preparation");
        Json warnings=Json::array();
        if(gen->source.at("schema")=="uc.capture-plan.v2")warnings.push_back("probe-pair passed own-fixture qualification; this target process/site set is not yet game-runtime verified.");
        Json result={{"ok",true},{"generation",next},{"plan_hash",gen->planHash},{"session_id",store->Id()},
            {"directory",store->Path()},{"warnings",warnings}};
        const uint64_t beforePublish=Clock();
        generations.push_back(gen);generationStaged=true;
        Meta({{"kind","plan_activation"},{"generation",next},{"plan_id",gen->planId},{"plan_revision",gen->revision},
              {"plan_hash",gen->planHash},{"qpc",beforePublish},{"wall_clock_utc",WallClockUtc()},{"source",gen->source},{"bindings",gen->bindings},
              {"publication_gap_begin_qpc",beforePublish},{"publication_commit","after-durable-activation-record"},
              {"cross_backend_atomic",false}});
        FlushMetaDurable();

        // Publication below is allocation-free and non-throwing. Coverage uses
        // the measured commit boundary, not the earlier manifest preparation.
        const uint64_t published=Clock();auto previous=active.load(std::memory_order_acquire);
        if(previous)for(auto& p:previous->points)if(!p->coverageEnd)p->coverageEnd=published;
        for(auto& p:gen->points)p->coverageBegin=published;
        generationCounter=next;moduleInvalid=false;lastModuleCheck=published;
        active.store(gen,std::memory_order_release);admitting.store(true,std::memory_order_release);
        return result;
    }catch(...){
        if(generationStaged&&!generations.empty()&&generations.back()==gen)generations.pop_back();
        for(auto it=added.rbegin();it!=added.rend();++it){auto* h=*it;try{Detach(*h);}catch(...){h->conflict=true;}}
        throw;}
}
Json Runtime::QualifySites(const Json& request){std::lock_guard lock(stateMutex);
    Require(!stopRequested.load()&&!clean&&!closeInitiated,"session is draining/stopped");
    Require(request.is_object()&&request.value("schema","")=="uc.probe-site-qualification.v1","qualification schema");
    Require(request.contains("qualification_id")&&request.at("qualification_id").is_string()&&
        !request.at("qualification_id").get<std::string>().empty(),"qualification id required");
    Require(hot.entrants.load()==0,"callbacks are active");
    for(const auto& h:hooks)Require(!h->owned&&!h->listener&&!h->conflict,"qualification requires no resident platform hooks");
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
    Require(GetProcessMitigationPolicy(GetCurrentProcess(),ProcessControlFlowGuardPolicy,&cfg,sizeof(cfg))!=FALSE,
        "target CFG policy query failed");
    Require(GetProcessMitigationPolicy(GetCurrentProcess(),ProcessUserShadowStackPolicy,&cet,sizeof(cet))!=FALSE,
        "target CET policy query failed");
    FILETIME created{},exited{},kernel{},user{};Require(GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)!=FALSE,"process identity query");
    ULARGE_INTEGER creation{};creation.LowPart=created.dwLowDateTime;creation.HighPart=created.dwHighDateTime;
    struct Bound {std::string alias,image,sha,path;uint64_t base=0,size=0;};
    std::unordered_map<std::string,Bound> modules;
    std::vector<ModuleRef> moduleRefs;
    Require(request.contains("modules")&&request.at("modules").is_object()&&!request.at("modules").empty(),"modules required");
    moduleRefs.reserve(request.at("modules").size());
    for(auto it=request.at("modules").begin();it!=request.at("modules").end();++it){auto image=it.value().at("image").get<std::string>();
        auto expected=it.value().at("sha256").get<std::string>();Require(expected.size()==64,"module sha256");
        HMODULE handle=nullptr;if(!GetModuleHandleExW(0,Utf8(image).wstring().c_str(),&handle))throw std::runtime_error("WAITING_MODULE:"+image);
        moduleRefs.emplace_back(handle);
        MODULEINFO info{};Require(GetModuleInformation(GetCurrentProcess(),handle,&info,sizeof(info))!=FALSE,"module information");
        wchar_t path[32768];auto pathSize=GetModuleFileNameW(handle,path,(DWORD)std::size(path));
        Require(pathSize>0&&pathSize<std::size(path),"module path unavailable or truncated");auto actual=FileSha(path);
        Require(actual==expected,"loaded module hash mismatch");modules.emplace(it.key(),Bound{it.key(),image,actual,fs::path(path).string(),
            (uint64_t)info.lpBaseOfDll,(uint64_t)info.SizeOfImage});}
    Require(request.contains("sites")&&request.at("sites").is_array()&&!request.at("sites").empty(),"sites required");
    Json rows=Json::array();std::vector<std::pair<uint64_t,uint64_t>> reservations;
    for(const auto& site:request.at("sites")){
        Require(site.is_object()&&site.at("direct_interior_edge_free")==true,"direct interior edge freedom required");
        auto id=site.at("id").get<std::string>(),alias=site.at("module").get<std::string>();Require(!id.empty(),"site id required");
        Require(modules.contains(alias),"unknown qualification module");const auto& module=modules.at(alias);
        uint64_t rva=site.at("rva").get<uint64_t>();Require(rva<module.size&&module.size-rva>=32,"site outside loaded module");
        auto prefix=Unhex(site.at("verified_source_prefix").get<std::string>());Require(prefix.size()>=32,"32 source bytes required");
        uint64_t semantic=site.at("semantic_safe_span").get<uint64_t>();Require(semantic>=16&&semantic<=prefix.size(),"semantic safe span");
        bool allow5=false,allow16=false;for(const auto& span:site.at("safe_redirect_spans")){auto n=span.get<uint64_t>();allow5|=n==5;allow16|=n==16;}
        Require(allow5&&allow16,"both current backend redirect classes must be safe before qualification");
        uint64_t address=Add(module.base,rva);for(const auto& old:reservations)Require(old.second<=address||address+16<=old.first,
            "qualification site reservations overlap");reservations.push_back({address,address+16});
        Bytes before(prefix.size());Require(Read(address,before.data(),before.size()),"qualification source unreadable");
        Require(before==prefix,"qualification source prefix mismatch");auto holder=std::make_unique<Hook>();auto& hook=*holder;
        hook.id=(uint32_t)hooks.size();hook.target=address;hook.original=address;hook.backend=Backend::GumProbe;
        hook.listener=gum_make_probe_listener(OnProbe,&hook,nullptr);Require(hook.listener!=nullptr,"qualification listener allocation");
        bool attached=false;uint64_t begin=Clock();
        try{GumAttachOptions options{};auto status=gum_interceptor_attach(interceptor,(void*)address,hook.listener,&options);
            if(status!=GUM_ATTACH_OK)throw std::runtime_error("qualification probe listener installation failed:"+std::to_string(status));attached=true;
            Bytes installed(prefix.size());Require(Read(address,installed.data(),installed.size()),"qualification installed state unreadable");
            std::vector<size_t> changed;for(size_t i=0;i<installed.size();++i)if(installed[i]!=before[i])changed.push_back(i);
            Require(!changed.empty(),"qualification produced no observable redirect");
            uint64_t required=installed[0]==0xe9?5:16,relocated=changed.back()+1;
            Require((required==5&&allow5)||(required==16&&allow16),"actual redirect class was not pre-authorized");
            Require(required<=semantic&&relocated<=semantic,"actual relocated span exceeds proven semantic-safe window");
            gum_interceptor_detach(interceptor,hook.listener);attached=false;
            Require(gum_interceptor_flush_listener(interceptor,hook.listener),"qualification listener references pending");
            Bytes restored(prefix.size());Require(Read(address,restored.data(),restored.size()),"qualification restored state unreadable");
            Require(restored==before,"qualification did not restore exact source bytes");
            rows.push_back({{"id",id},{"module",alias},{"module_path",module.path},{"module_sha256",module.sha},
                {"module_base",module.base},{"rva",rva},{"target",address},{"qpc_begin",begin},{"qpc_end",Clock()},
                {"verified_source_prefix",Hex(before.data(),before.size())},{"installed_state",Hex(installed.data(),installed.size())},
                {"restored_state",Hex(restored.data(),restored.size())},{"changed_byte_offsets",changed},
                {"backend_patch_contract",{{"backend_build_hash","23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475"},
                    {"redirect_kind",required==5?"near":"far"},{"required_redirect_span",required},{"relocated_span",relocated},
                    {"fault_in_relocated_span_test","passed-own-fixture"},{"architectural_rsp_test","passed-own-fixture"},
                    {"cet_cfg_test","target-runtime-observed"},{"probe_rva",rva},
                    {"target_process_identity",{{"pid",GetCurrentProcessId()},{"creation_time_100ns",creation.QuadPart}}},
                    {"target_process_policy",{{"cfg_enabled",cfg.EnableControlFlowGuard!=0},
                        {"cet_user_shadow_stack_enabled",cet.EnableUserShadowStack!=0},
                        {"cet_user_shadow_stack_strict",cet.EnableUserShadowStackStrictMode!=0}}}}},
                {"source_restoration_verified",true},{"target_site_patch_verified",true},
                {"incoming_indirect_edges_complete",false},{"observation_semantics_verified",false}});
        }catch(...){if(attached)gum_interceptor_detach(interceptor,hook.listener);hook.owned=false;hook.detached=true;
            if(gum_interceptor_flush_listener(interceptor,hook.listener)){g_object_unref(hook.listener);hook.listener=nullptr;}
            else {hook.error="qualification listener drain pending";Meta({{"kind","qualification_listener_drain_pending"},
                    {"hook_id",hook.id},{"target",hook.target},{"qpc",Clock()}});hooks.push_back(std::move(holder));}
            throw;}
        g_object_unref(hook.listener);hook.listener=nullptr;
    }
    return {{"ok",true},{"schema","uc.target-site-qualification-result.v1"},
        {"qualification_id",request.at("qualification_id")},{"backend_build_hash","23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475"},
        {"target_process",{{"pid",GetCurrentProcessId()},{"creation_time_100ns",creation.QuadPart},{"cfg_enabled",cfg.EnableControlFlowGuard!=0},
            {"cet_user_shadow_stack_enabled",cet.EnableUserShadowStack!=0},{"cet_user_shadow_stack_strict",cet.EnableUserShadowStackStrictMode!=0}}},
        {"sites",rows},{"game_runtime_verified",false},{"target_patch_contracts_verified",true},
        {"capture_generation_published",false},{"behavior_events_collected",false}};
}
void Runtime::NoteAdmissionDrop() noexcept {
    // Independent counter for callbacks observed while admission was closed
    // (stop/publication window): without it, "zero events" and "not called"
    // are indistinguishable in the sealed evidence.
    auto qpc=Clock();admission.drops.fetch_add(1,std::memory_order_relaxed);
    uint64_t first=0;admission.first.compare_exchange_strong(first,qpc,std::memory_order_relaxed);
    auto l=admission.last.load();while(qpc>l&&!admission.last.compare_exchange_weak(l,qpc)){}}
void Runtime::ReportAdmissionWindow(){
    Json key={{"drops",admission.drops.load()},{"first_qpc",admission.first.load()},
        {"last_qpc",admission.last.load()}};
    if(key!=lastAdmissionNote){
        Meta(Json{{"kind","admission_window"},{"qpc",Clock()},{"drops",key["drops"]},
            {"first_qpc",key["first_qpc"]},{"last_qpc",key["last_qpc"]}});
        lastAdmissionNote=std::move(key);}}
namespace {
// O(1) fast path: revalidate the module list only when the process-wide
// module epoch serial moved since the last verification.
bool ModulesLive(const Generation& generation) noexcept {
    for(unsigned attempt=0;attempt<2;++attempt){const auto epoch=ModuleEpochSerial();
        if(epoch==generation.moduleVerifiedEpoch.load(std::memory_order_acquire))return true;
        for(const auto& m:generation.modules)if(!ModuleStillLoaded(m))return false;
        // Never cache an epoch that was observed only after validation: an
        // unload between the walk and the second serial read must retry/drop.
        if(ModuleEpochSerial()!=epoch)continue;
        const_cast<Generation&>(generation).moduleVerifiedEpoch.store(epoch,std::memory_order_release);return true;}
    return false;}
}
void Runtime::Begin(Hook& h,const Abi& abi,Token& token) noexcept {
    hot.entrants.fetch_add(1);
    auto drop=[&](){NoteAdmissionDrop();hot.entrants.fetch_sub(1);};
    if(terminalCallbacks.load(std::memory_order_acquire)){hot.entrants.fetch_sub(1);return;}
    if(store->SealFailedFast()){admitting.store(false,std::memory_order_release);drop();return;}
    if(!admitting.load()){drop();return;}
    auto gen=active.load(std::memory_order_acquire);
    if(!gen||h.id>=gen->byHook.size()||gen->byHook[h.id].size()!=1){hot.entrants.fetch_sub(1);return;}
    if(!ModulesLive(*gen)){drop();return;}
    token.generation=gen;token.point=gen->byHook[h.id].front().get();auto& p=*token.point;
    const_cast<Generation*>(gen.get())->inFlight.fetch_add(1);p.inFlight.fetch_add(1);
    token.invocation=token.probe?0:hot.callIds.fetch_add(1);
    Parent(token.invocation,abi.stackMarker,token.parent,token.parentKnown,!token.probe);
    token.cell=p.Acquire();uint64_t id=hot.eventIds.fetch_add(1);
    if(token.cell){auto& e=token.cell->enter;e.id=id;e.invocation=token.invocation;e.parent=token.parent;e.parentKnown=token.parentKnown;
        if(Capture(p,e,abi,abi,1))token.cell->flags.fetch_or(1,std::memory_order_release);
        else{token.cell->state.store(0,std::memory_order_release);p.freeSlots.fetch_add(1,std::memory_order_release);token.cell=nullptr;}}
    else p.loss.Note(Clock(),1,0,true);
    hot.entrants.fetch_sub(1);
}
void Runtime::Probe(Hook& h,const Abi& abi) noexcept {
    hot.entrants.fetch_add(1);
    auto finish=[&](const PairFrame& frame,bool absent){auto* payload=pairs.Find(frame.invocation);if(!payload)return;
        auto gen=payload->generation;auto& p=*payload->point;
        if(gen->reclaimed.load(std::memory_order_acquire)){
            for(uint32_t i=0;i<payload->exitHookCount;++i)payload->exitHooks[i]->executing.fetch_sub(1);
            pairs.Release(*payload);return;}
        if(payload->cell){auto& e=payload->cell->leave;e.id=hot.eventIds.fetch_add(1);e.invocation=frame.invocation;
            e.parent=payload->cell->enter.parent;e.parentKnown=payload->cell->enter.parentKnown;e.exitHookId=absent?UINT32_MAX:h.id;
            if(absent){e.abi=abi;e.qpc=Clock();e.endQpc=e.qpc;e.tid=GetCurrentThreadId();e.used=0;e.exceptional=false;
                for(auto& read:e.reads)read={};payload->cell->flags.fetch_or(2|16|32,std::memory_order_release);}
            else {Capture(p,e,abi,payload->cell->enter.abi,2);payload->cell->flags.fetch_or(2|16,std::memory_order_release);}}
        else p.loss.Note(Clock(),1,0,true);
        for(uint32_t i=0;i<payload->exitHookCount;++i)payload->exitHooks[i]->executing.fetch_sub(1);
        p.inFlight.fetch_sub(1);const_cast<Generation*>(gen.get())->inFlight.fetch_sub(1);pairs.Release(*payload);};
    // Shared epilogues may match more frames than one batch span: drain in
    // loops so every extracted frame is accounted and none wedges the drain.
    for(;;){size_t closed=pairs.ledger.Close(h.id,pairs.extracted);if(!closed)break;
        for(size_t i=0;i<closed;++i)finish(pairs.extracted[i],false);}
    for(;;){size_t absent=pairs.ledger.PruneAbsent(abi.stackMarker,pairs.extracted);if(!absent)break;
        for(size_t i=0;i<absent;++i)finish(pairs.extracted[i],true);}
    auto drop=[&](){NoteAdmissionDrop();hot.entrants.fetch_sub(1);};
    if(terminalCallbacks.load(std::memory_order_acquire)){hot.entrants.fetch_sub(1);return;}
    if(store->SealFailedFast()){admitting.store(false,std::memory_order_release);drop();return;}
    if(!admitting.load()){drop();return;}
    auto gen=active.load(std::memory_order_acquire);
    if(!gen||h.id>=gen->byHook.size()||gen->byHook[h.id].empty()){hot.entrants.fetch_sub(1);return;}
    if(!ModulesLive(*gen)){drop();return;}
    size_t pairNeeded=0;for(const auto& point:gen->byHook[h.id])if(h.id==point->hookId&&point->mode==PointMode::ProbePair)++pairNeeded;
    const bool pairCapacity=pairs.ledger.GroupCount()<gen->threadNestingLimit&&
        pairs.ledger.Size()<=gen->pairFrameLimit&&pairNeeded<=gen->pairFrameLimit-pairs.ledger.Size();
    const uint64_t group=hot.callIds.fetch_add(1),parent=pairs.ledger.ObservedParent(abi.stackMarker);
    for(const auto& point:gen->byHook[h.id]){auto& p=*point;
        if(h.id!=p.hookId)continue; // Exit subscriptions were handled above.
        if(p.mode==PointMode::Single){Token token;token.probe=true;token.generation=gen;token.point=&p;
            const_cast<Generation*>(gen.get())->inFlight.fetch_add(1);p.inFlight.fetch_add(1);token.cell=p.Acquire();const uint64_t id=hot.eventIds.fetch_add(1);
            if(token.cell){auto& e=token.cell->enter;e.id=id;e.invocation=0;e.parent=0;e.parentKnown=false;
                if(Capture(p,e,abi,abi,1))token.cell->flags.fetch_or(1|8|16,std::memory_order_release);
                else{token.cell->state.store(0,std::memory_order_release);p.freeSlots.fetch_add(1,std::memory_order_release);token.cell=nullptr;}}
            else p.loss.Note(Clock(),1,0,true);
            p.inFlight.fetch_sub(1);const_cast<Generation*>(gen.get())->inFlight.fetch_sub(1);continue;}
        if(!pairCapacity){p.loss.Note(Clock(),2,0,true);continue;}
        const uint64_t invocation=hot.callIds.fetch_add(1);auto* payload=pairs.Reserve(invocation);
        if(!payload){p.loss.Note(Clock(),2,0,true);continue;}
        std::array<uint32_t,8> exits{};
        for(size_t i=0;i<p.exits.size();++i)exits[i]=p.exits[i].hookId;
        auto opened=pairs.ledger.Open(p.logicalIdentity,gen->generation,group,invocation,abi.stackMarker,
            std::span<const uint32_t>(exits.data(),p.exits.size()));
        if(opened!=PairOpenResult::Opened){pairs.Release(*payload);p.loss.Note(Clock(),2,0,true);continue;}
        payload->generation=gen;payload->point=&p;payload->cell=p.Acquire();payload->exitHookCount=(uint32_t)p.exits.size();
        p.inFlight.fetch_add(1);const_cast<Generation*>(gen.get())->inFlight.fetch_add(1);
        for(size_t i=0;i<p.exits.size();++i){payload->exitHooks[i]=(Hook*)p.exits[i].runtimeHook;payload->exitHooks[i]->executing.fetch_add(1);}
        if(payload->cell){auto& e=payload->cell->enter;e.id=hot.eventIds.fetch_add(1);e.invocation=invocation;e.parent=parent;e.parentKnown=parent!=0;
            if(Capture(p,e,abi,abi,1))payload->cell->flags.fetch_or(1,std::memory_order_release);
            else{
                // Entry predicate filtered this call: undo the just-opened
                // frame so no exit-side ghost record is emitted later.
                pairs.ledger.Abandon(invocation);
                payload->cell->state.store(0,std::memory_order_release);p.freeSlots.fetch_add(1,std::memory_order_release);
                for(uint32_t i=0;i<payload->exitHookCount;++i)payload->exitHooks[i]->executing.fetch_sub(1);
                pairs.Release(*payload);p.inFlight.fetch_sub(1);const_cast<Generation*>(gen.get())->inFlight.fetch_sub(1);
                continue;}}
        else p.loss.Note(Clock(),1,0,true);
    }
    hot.entrants.fetch_sub(1);
}
void Runtime::End(Hook&,const Abi& abi,Token& token,bool exceptional) noexcept {
    if(!token.point)return;
    // Entrants guard: forces drain-reclaim in Tick to wait for this call, so
    // the generation pointer and its counters stay stable while we touch them.
    hot.entrants.fetch_add(1);
    if(token.generation->reclaimed.load(std::memory_order_acquire)){Pop(token.invocation);hot.entrants.fetch_sub(1);return;}
    auto& p=*token.point;
    if(token.probe){if(token.cell)token.cell->flags.fetch_or(8|16,std::memory_order_release);}
    else {uint64_t id=hot.eventIds.fetch_add(1);if(token.cell){auto& e=token.cell->leave;e.id=id;e.invocation=token.invocation;e.parent=token.parent;e.parentKnown=token.parentKnown;
            Capture(p,e,abi,token.cell->enter.abi,2);e.exceptional=exceptional;token.cell->flags.fetch_or(2|16,std::memory_order_release);}
        else p.loss.Note(Clock(),1,0,true);Pop(token.invocation);}
    p.inFlight.fetch_sub(1);const_cast<Generation*>(token.generation.get())->inFlight.fetch_sub(1);
    hot.entrants.fetch_sub(1);
}
void Runtime::WriteRecord(const Generation& gen,Point& point,const Record& e,const char* kind){
    Json regs=Json::object(),args=Json::array(),xmm=Json::object(),reads=Json::array();
    for(unsigned i=0;i<RegCount;++i)if(e.abi.registerMask&(1U<<i))regs[RegNames[i]]=e.abi.regs[i];
    for(unsigned i=0;i<8;++i)if(e.abi.argumentMask&(1U<<i))args.push_back({{"index",i},{"bits",e.abi.args[i]}});
    for(unsigned i=0;i<16;++i)if(e.abi.xmmMask&(1U<<i))xmm[std::to_string(i)]=Hex(e.abi.xmm[i],16);
    unsigned failures=0,truncated=0;
    for(size_t i=0;i<e.reads.size();++i){const auto& r=e.reads[i];reads.push_back({{"id",point.ops[i].id},{"address",r.address},{"value",r.value},
        {"status",r.status},{"offset",r.begin},{"length",r.bytes},{"declared_count",r.count}});
        if(r.status==2||r.status==3||r.status==5)++failures;if(r.status==4)++truncated;}
    Json event={{"schema","uc.event.v1"},{"event_id",e.id},{"kind",kind},{"point",point.id},{"generation",gen.generation},
        {"qpc",e.qpc},{"read_end_qpc",e.endQpc},{"tid",e.tid},{"observed_parent",e.parent},{"parent_known",e.parentKnown},
        {"snapshot_atomic",false},{"exceptional",e.exceptional},{"reads",reads},{"read_failures",failures},{"truncated",truncated},
        {"raw_abi",{{"registers",regs},{"xmm",xmm},{"register_mask",e.abi.registerMask},{"xmm_mask",e.abi.xmmMask}}},
        {"semantic_interpretation",{{"version",point.backend==Backend::Slot?"uc.legacy-abi.v1":"uc.raw-only.v1"},
            {"abi",point.abi},{"validated_argument_bits",args},{"source_plan_hash",gen.planHash}}}};
    if(point.backend!=Backend::GumProbe||point.mode==PointMode::ProbePair)event["invocation_id"]=e.invocation;
    if(e.exitHookId!=UINT32_MAX)for(const auto& exit:point.exits)if(exit.hookId==e.exitHookId){
        event["normal_exit"]={{"exit_site_id",exit.id},{"hook_id",e.exitHookId},{"contract",exit.contract}};break;}
    if(e.legacySize){event["legacy_snapshot"]={{"reader",point.legacyReader},{"offset",e.legacyOffset},{"length",e.legacySize},
        {"read_failures",e.legacyFailures},{"truncated",e.legacyTruncated},{"source_plan_hash",gen.planHash}};}
    try{store->Event(event,e.bytes.data(),e.used);}
    catch(const StoreBackpressure&){point.loss.Note(Clock(),1,e.used,false,LossReason::QueueOverflow);}
    catch(...){point.loss.Note(Clock(),1,e.used,false,LossReason::StorageFailure);throw;}
}
Json Runtime::PointSnapshot(const Generation& gen,const Point& p){
    auto snapshot=p.loss.Snapshot(p.id,gen.generation);
    // Deliberate predicate filtering is reported beside loss but is not loss.
    snapshot["filtered_by_plan"]=p.filtered.load();return snapshot;}
void Runtime::ReportLoss(const Generation& gen,Point& p,uint64_t now){
    auto snapshot=PointSnapshot(gen,p);
    if(snapshot["last_qpc"]!=0&&snapshot!=p.lastReportedLoss){
        // Bypasses the ordinary event pool. These are cumulative, not deltas to
        // add to earlier summaries; the original independent counters remain.
        store->Meta({{"kind","loss_summary"},{"schema","uc.LossSummary.v1"},{"qpc",now},
            {"counting","cumulative-per-point-generation"},{"loss",snapshot}});p.lastReportedLoss=std::move(snapshot);}
}
void Runtime::Tick(){
    bool failedStorage=false;{std::lock_guard errorLock(errorMutex);failedStorage=!storageError.empty();}
    std::lock_guard lock(stateMutex);
    if(clean)return;
    if(failedStorage){
        // Failed persistence must not prevent independent hook cleanup after an
        // explicit stop. Never claim a clean session seal in this branch.
        admitting.store(false,std::memory_order_release);
        // Account every completed half that can no longer reach the store.
        // Marking the half consumed prevents repeated cumulative increments on
        // later ticks; in-flight calls are handled when their leave arrives.
        for(auto& gen:generations)for(auto& p:gen->points)for(uint32_t i=0;i<p->poolSize;++i){Cell& c=p->pool[i];
            if(c.state.load(std::memory_order_acquire)!=2)continue;auto flags=c.flags.load(std::memory_order_acquire);
            if((flags&1)&&!(flags&4)){p->loss.Note(c.enter.qpc,1,c.enter.used,false,LossReason::StorageFailure);c.flags.fetch_or(4,std::memory_order_release);}
            flags=c.flags.load(std::memory_order_acquire);
            if((flags&2)&&!(flags&8)){p->loss.Note(c.leave.qpc,1,c.leave.used,false,LossReason::StorageFailure);c.flags.fetch_or(8,std::memory_order_release);}
            if((c.flags.load(std::memory_order_acquire)&(4|8|16))==(4|8|16)){c.state.store(0,std::memory_order_release);
                p->freeSlots.fetch_add(1,std::memory_order_release);}}
        if(stopRequested.load()&&hot.entrants.load()==0){bool busy=false;for(auto& g:generations)busy|=g->inFlight.load()!=0;
            if(!busy)for(auto& h:hooks){try{Detach(*h);
                if(h->listener&&h->detached&&gum_interceptor_flush_listener(interceptor,h->listener)){g_object_unref(h->listener);h->listener=nullptr;}}
                catch(const std::exception& e){h->conflict=true;h->error=e.what();}}}
        return;
    }
    try{
        if(closeInitiated){if(auto error=store->SealErrorText();!error.empty())throw std::runtime_error(error);
            if(store->Sealed()){forcedTerminal=closeForced;clean=true;}return;}
        {std::deque<Json> rows;{std::lock_guard metadataLock(metaMutex);rows.swap(metadata);}for(auto& row:rows)store->Meta(row);}
        for(const auto& gen:generations)for(const auto& p:gen->points)for(uint32_t i=0;i<p->poolSize;++i){Cell& c=p->pool[i];
            if(c.state.load(std::memory_order_acquire)!=2)continue;auto flags=c.flags.load(std::memory_order_acquire);
            if((flags&1)&&!(flags&4)){try{WriteRecord(*gen,*p,c.enter,p->backend==Backend::GumProbe&&p->mode==PointMode::Single?"probe":"enter");}
                catch(...){c.flags.fetch_or(4,std::memory_order_release);throw;}c.flags.fetch_or(4);}
            flags=c.flags.load(std::memory_order_acquire);
            if((flags&2)&&!(flags&8)){try{WriteRecord(*gen,*p,c.leave,(flags&32)?"frame_absent_after_observed_point":"leave");}
                catch(...){c.flags.fetch_or(8,std::memory_order_release);throw;}c.flags.fetch_or(8);}
            if((c.flags.load()&(4|8|16))==(4|8|16)){c.state.store(0,std::memory_order_release);
                p->freeSlots.fetch_add(1,std::memory_order_release);}}
        auto current=active.load(std::memory_order_acquire);
        if(current&&!moduleInvalid){bool valid=true;for(const auto& m:current->modules)valid&=ModuleStillLoaded(m);
            if(valid)lastModuleCheck=Clock();else {moduleInvalid=true;admitting.store(false);
                for(auto& p:current->points)p->coverageEnd=lastModuleCheck;
                Meta({{"kind","module_binding_invalidated"},{"generation",current->generation},{"last_verified_qpc",lastModuleCheck},
                    {"noticed_qpc",Clock()},{"exact_unload_qpc",nullptr}});
                for(auto& h:hooks)for(const auto& m:current->modules)if(!ModuleStillLoaded(m)&&
                    ((h->target>=m.base&&h->target<m.base+m.size)||(h->original>=m.base&&h->original<m.base+m.size))){
                    h->conflict=true;h->error="hook module load instance changed; no stale mapping writes";}}}
        if(hot.entrants.load()==0){for(auto& h:hooks){bool wanted=!stopRequested.load()&&!moduleInvalid&&current&&h->id<current->byHook.size()&&!current->byHook[h->id].empty();
            bool busy=h->executing.load()!=0;for(const auto& gen:generations)if(h->id<gen->byHook.size())
                for(const auto& point:gen->byHook[h->id])if(point->inFlight.load())busy=true;
            if(!wanted&&!busy)Detach(*h);
            if(h->listener&&h->detached&&gum_interceptor_flush_listener(interceptor,h->listener)){
                g_object_unref(h->listener);h->listener=nullptr;}}}
        // A token pins its generation even after End until the backend callback
        // returns. Reclaim only after all tokens, publication readers and queued
        // records have released it. Keep a compact, durable loss/coverage ledger.
        if(hot.entrants.load()==0)for(auto it=generations.begin();it!=generations.end();){auto& gen=*it;
            bool empty=gen!=current&&gen.use_count()==1&&gen->inFlight.load()==0;
            if(empty)for(auto& p:gen->points)for(uint32_t i=0;i<p->poolSize;++i)if(p->pool[i].state.load())empty=false;
            if(empty){Archive(*gen);it=generations.erase(it);}else ++it;}
        uint64_t now=Clock();if(now-flushQpc>=Frequency()){
            store->Flush();Json loss=archivedLoss;for(const auto& gen:generations)for(const auto& p:gen->points){
                ReportLoss(*gen,*p,now);loss.push_back(PointSnapshot(*gen,*p));}
            store->Meta({{"kind","loss_checkpoint"},{"qpc",now},{"loss",loss},{"snapshot_atomic",false}});
            ReportAdmissionWindow();flushQpc=now;}
        if(stopRequested.load()&&!clean){
            if(forceRelease.load()&&hot.entrants.load()==0){
                // Explicit force is a terminal, unclean seal. Shared ownership
                // keeps generations alive for late paired/TLS cleanup, and
                // hooks that cannot be removed safely remain resident. No new
                // session may start in this process after this branch.
                for(auto& g:generations){uint64_t frames=g->inFlight.exchange(0);
                    if(frames)g->reclaimed.store(true,std::memory_order_release);
                    for(auto& p:g->points){uint64_t pointFrames=p->inFlight.exchange(0);
                        if(pointFrames)p->loss.Note(Clock(),pointFrames,0,true,LossReason::FrameTerminationUnknown);
                        for(uint32_t i=0;i<p->poolSize;++i){Cell& c=p->pool[i];
                            if(c.state.load(std::memory_order_acquire)!=2)continue;
                            auto flags=c.flags.load(std::memory_order_acquire);
                            if((flags&1)&&!(flags&4)){try{WriteRecord(*g,*p,c.enter,p->backend==Backend::GumProbe&&p->mode==PointMode::Single?"probe":"enter");}
                                catch(...){c.flags.fetch_or(4,std::memory_order_release);throw;}c.flags.fetch_or(4);}
                            c.flags.fetch_or(4|8|16,std::memory_order_release);c.state.store(0,std::memory_order_release);
                            p->freeSlots.fetch_add(1,std::memory_order_release);}}
                    Meta({{"kind","forced_drain_reclaim"},{"generation",g->generation},
                        {"assumed_unwound_frames",frames},{"operator_forced",true},{"qpc",Clock()}});}
                Json loss=archivedLoss;for(const auto& gen:generations)for(const auto& p:gen->points){
                    ReportLoss(*gen,*p,Clock());loss.push_back(PointSnapshot(*gen,*p));
                    store->Meta({{"kind","coverage"},{"point",p->id},{"generation",gen->generation},
                        {"begin_qpc",p->coverageBegin},{"end_qpc",p->coverageEnd?p->coverageEnd:stopQpc},{"complete",false}});}
                ReportAdmissionWindow();
                {std::deque<Json> rows;{std::lock_guard ml(metaMutex);rows.swap(metadata);}for(auto& row:rows)store->Meta(row);}
                terminalCallbacks.store(true,std::memory_order_release);
                store->BeginClose(loss,"STOPPED_FORCED");closeInitiated=true;closeForced=true;return;}
            uint64_t calls=0;for(auto& g:generations)calls+=g->inFlight.load();bool released=hot.entrants.load()==0&&calls==0;
            for(auto& h:hooks){if(h->owned||h->conflict||h->executing.load())released=false;
                if(h->listener&&h->detached&&!gum_interceptor_flush_listener(interceptor,h->listener))released=false;}
            if(released){Json loss=archivedLoss;for(const auto& gen:generations)for(const auto& p:gen->points){ReportLoss(*gen,*p,Clock());loss.push_back(PointSnapshot(*gen,*p));
                    store->Meta({{"kind","coverage"},{"point",p->id},{"generation",gen->generation},{"begin_qpc",p->coverageBegin},
                        {"end_qpc",p->coverageEnd?p->coverageEnd:stopQpc},{"complete",true}});}
                ReportAdmissionWindow();
                // Commit pending hook teardown metadata before the final session seal.
                {std::deque<Json> rows;{std::lock_guard ml(metaMutex);rows.swap(metadata);}for(auto& row:rows)store->Meta(row);}
                store->BeginClose(loss,"STOPPED_CLEAN");closeInitiated=true;closeForced=false;return;}}
    }catch(const std::exception& e){admitting.store(false,std::memory_order_release);std::lock_guard errorLock(errorMutex);storageError=e.what();
        // Attribution: persist the failure and any events the failing seal
        // dropped, so "disk full" is distinguishable from "crashed" offline.
        try{auto bufferedLost=store->DrainBufferedEventsLost();unattributedStorageLoss.fetch_add(bufferedLost,std::memory_order_relaxed);
            Json note={{"kind","storage_error"},{"error",storageError},{"qpc",Clock()},
            {"buffered_events_lost",bufferedLost}};
            store->Meta(std::move(note));store->FlushMeta();}catch(...){}}
}
void Runtime::Archive(const Generation& gen){for(auto& p:gen.points){ReportLoss(gen,*p,Clock());auto loss=PointSnapshot(gen,*p);archivedLoss.push_back(loss);
    store->Meta({{"kind","generation_point_retired"},{"generation",gen.generation},{"point",p->id},{"loss",loss},{"qpc",Clock()}});
    store->Meta({{"kind","coverage"},{"point",p->id},{"generation",gen.generation},{"begin_qpc",p->coverageBegin},
        {"end_qpc",p->coverageEnd},{"complete",true}});}}
void Runtime::NewSession(){
    // Called under stateMutex, and only after the previous session's clean seal.
    Require(clean,"previous session not clean");auto replacement=std::make_unique<Store>(outputRoot);
    active.store(nullptr);generations.clear();archivedLoss=Json::array();store=std::move(replacement);
    clean=false;forcedTerminal=false;closeInitiated=false;closeForced=false;stopRequested.store(false);forceRelease.store(false);terminalCallbacks.store(false);admitting.store(false);stopQpc=0;flushQpc=Clock();
    moduleInvalid=false;lastAdmissionNote=Json(nullptr);
    admission.drops.store(0);admission.first.store(0);admission.last.store(0);
    unattributedStorageLoss.store(0);
    Meta({{"kind","capabilities"},{"value",Capabilities()},{"continuation_generation",generationCounter}});
}
void Runtime::Stop(bool force){std::lock_guard lock(stateMutex);
    if(clean||closeInitiated)return;
    if(force&&!forceRelease.exchange(true))Meta({{"kind","force_stop_request"},{"qpc",Clock()}});
    if(stopRequested.exchange(true)){if(force)try{FlushMetaDurable();}catch(...){}return;}
    admitting.store(false);stopQpc=Clock();
    Meta({{"kind","stop_request"},{"qpc",stopQpc},{"operator_forced",force}});
    // The stop itself must stay acceptable under storage failure: a missing
    // durable stop_request line is detectable offline, a refused stop is not.
    try{FlushMetaDurable();}catch(...){}}
void Runtime::Start(){std::lock_guard lock(stateMutex);Require(!stopRequested.load()&&!clean,"session is draining/stopped");
    {std::lock_guard errorLock(errorMutex);Require(storageError.empty(),"storage failed");}Require(!store->SealFailed(),"storage failed");
    Require(active.load()!=nullptr,"apply a plan first");admitting.store(true);}
void Runtime::Mark(const std::string& label){std::lock_guard lock(stateMutex);Require(!clean&&!stopRequested.load()&&!closeInitiated,"session is draining/stopped");
    {std::lock_guard errorLock(errorMutex);Require(storageError.empty(),"storage failed");}Require(!store->SealFailed(),"storage failed");
    Meta({{"kind","user_mark"},{"label",label},{"qpc",Clock()},{"native_semantics",false}});FlushMetaDurable();}
Json Runtime::Status()const{std::lock_guard lock(stateMutex);Json loss=archivedLoss,ownership=Json::array(),timing=Json::array();uint64_t calls=0,queued=0,memory=0;
    for(const auto& gen:generations){calls+=gen->inFlight.load();for(const auto& p:gen->points){loss.push_back(PointSnapshot(*gen,*p));
        memory+=p->poolSize*(sizeof(Cell)+2*(p->blobCapacity+p->ops.size()*sizeof(ReadResult)));
        timing.push_back({{"point",p->id},{"generation",gen->generation},{"samples",p->readSamples.load()},
            {"read_program_ticks",p->readTicks.load()},{"read_program_max_ticks",p->readMax.load()},
            {"filtered_by_plan",p->filtered.load()}});
        for(uint32_t i=0;i<p->poolSize;++i)if(p->pool[i].state.load())++queued;}}
    for(const auto& h:hooks)ownership.push_back({{"hook_id",h->id},{"target",h->target},{"reserved_span",h->reservedSpan},
        {"required_redirect_span",h->patchSpan},{"owned",h->owned},{"conflict",h->conflict},
        {"detached",h->detached},{"executing",h->executing.load()},{"error",h->error}});
    PROCESS_MEMORY_COUNTERS_EX pm{};pm.cb=sizeof(pm);GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&pm,sizeof(pm));
    std::lock_guard errorLock(errorMutex);auto persistedError=storageError.empty()?store->SealErrorText():storageError;
    return {{"ok",true},{"state",forcedTerminal?"STOPPED_FORCED":clean?"STOPPED_CLEAN":stopRequested.load()?"DRAIN_PENDING":
            !persistedError.empty()?"STORAGE_FAILED":moduleInvalid?"MODULE_REBIND_PENDING":active.load()?"RUNNING":"IDLE"},
        {"generation",generationCounter},{"in_flight",calls},{"queued_cells",queued},{"loss",loss},{"hooks",ownership},
        {"resident_generations",generations.size()},{"preallocated_record_bytes",memory},
        {"read_timing",timing},{"qpc_frequency",Frequency()},
        {"admission_window_drops",admission.drops.load()},
        {"unattributed_storage_loss_events",unattributedStorageLoss.load()},
        {"process_working_set_bytes",pm.WorkingSetSize},{"process_private_bytes",pm.PrivateUsage},{"storage",store->Status()},
        {"storage_error",persistedError},{"directory",store->Path()},
        {"session_id",store->Id()},{"automatic_stop",false}};
}
Json Runtime::RebindPlan()const{std::lock_guard lock(stateMutex);if(!moduleInvalid||stopRequested.load())return nullptr;
    for(auto& g:generations)if(g->inFlight.load())return nullptr;
    for(auto& h:hooks)if(h->owned||h->conflict||h->listener||h->executing.load())return nullptr;
    auto gen=active.load(std::memory_order_acquire);return gen?gen->source:Json(nullptr);}
void Runtime::FlushMetaDurable(){
    // Called under stateMutex from control paths: queue the runtime metadata
    // into the store and force it onto the disk before the call returns.
    std::deque<Json> rows;{std::lock_guard ml(metaMutex);rows.swap(metadata);}
    for(auto& row:rows)store->Meta(std::move(row));
    store->FlushMeta();}
uint64_t Runtime::SlotOriginal(uint64_t address)const{std::lock_guard lock(stateMutex);uint64_t value=0;
    Require(Read(address,&value,8),"live data slot unreadable");
    if(!value)throw std::runtime_error("WAITING_TARGET:uninitialized data slot");
    for(auto& h:hooks)if(h->target==address&&h->backend==Backend::Slot&&h->owned&&value==(uint64_t)h->wrapper)return h->original;
    return value;}
}
