#include "plan.h"
#include "readers.h"
#include <algorithm>
#include <set>
namespace uc {
namespace {
constexpr const char* GumBuildHash="23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475";

void CompileRetention(Point& p,const Json& observation,const std::unordered_map<std::string,Module>& modules,
                      const std::function<void(const Json&)>& evidence){
    if(!observation.contains("retention"))return;
    const auto& retention=observation.at("retention");Require(retention.is_object(),"retention must be an object");
    const auto mode=retention.at("mode").get<std::string>();
    Require(mode=="first_per_entry_return_address"||mode=="first_per_composite_key","unsupported retention mode");
    auto capacity=U64(retention.at("max_keys"));
    Require(capacity&&capacity<=65536&&(capacity&(capacity-1))==0,"retention max_keys must be a power of two <= 65536");
    Require(p.backend==Backend::GumProbe,"return-address retention requires an instruction probe");
    for(const auto& op:p.ops)Require(!op.hasPredicate,"return-address retention cannot be combined with read predicates");
    if(retention.contains("exact_callers")){const auto& callers=retention.at("exact_callers");
        Require(callers.is_array()&&callers.size()<=256,"retention exact_callers must contain at most 256 rows");
        for(const auto& caller:callers){evidence(caller);const auto& module=modules.at(caller.at("module").get<std::string>());
            const auto rva=U64(caller.at("return_rva"));Require(rva<module.size,"exact caller return RVA outside module");
            p.exactCallerAddresses.push_back(Add(module.base,rva));}
        std::sort(p.exactCallerAddresses.begin(),p.exactCallerAddresses.end());
        Require(std::adjacent_find(p.exactCallerAddresses.begin(),p.exactCallerAddresses.end())==p.exactCallerAddresses.end(),
            "duplicate exact caller return address");}
    Require(p.mode==PointMode::Single||!p.exactCallerAddresses.empty(),
        "probe-pair retention requires at least one exact caller gate");
    if(mode=="first_per_entry_return_address"){
        Require(!retention.contains("key"),"legacy return-address retention cannot declare a composite key");
        p.retention=RetentionMode::FirstPerEntryReturnAddress;p.retentionKeyPartCount=1;
        p.retentionKeyParts[0].kind=RetentionKeyKind::EntryReturnAddress;
    }else{
        const auto& key=retention.at("key");Require(key.is_array()&&key.size()>=2&&key.size()<=MaxRetentionKeyParts,
            "composite retention key must contain 2..4 raw parts");
        Require(key.front().at("kind")=="entry_return_address",
            "composite retention key must begin with entry_return_address");
        std::set<std::string> identities;
        for(const auto& item:key){evidence(item);RetentionKeyPart part;auto kind=item.at("kind").get<std::string>();
            if(kind=="entry_return_address")part.kind=RetentionKeyKind::EntryReturnAddress;
            else if(kind=="register"){
                part.kind=RetentionKeyKind::Register;auto name=item.at("register").get<std::string>();bool found=false;
                for(uint32_t i=0;i<RegCount;++i)if(name==RegNames[i]){part.registerIndex=i;found=true;break;}
                Require(found,"composite retention key register");}
            else throw std::runtime_error("unsupported composite retention key part");
            part.mask=item.contains("mask")?U64(item.at("mask")):~0ull;
            auto identity=kind+(kind=="register"?":"+item.at("register").get<std::string>():"");
            Require(identities.insert(identity).second,"duplicate composite retention key part");
            p.retentionKeyParts[p.retentionKeyPartCount++]=part;}
        Require(p.retentionKeyPartCount>=2,"composite retention key requires identity beyond caller");
        p.retention=RetentionMode::FirstPerCompositeKey;
    }
    p.aggregateCapacity=(uint32_t)capacity;
}

void CompilePredicate(const Json& read,ReadOp& op){
    if(!read.contains("when"))return;
    const auto& when=read.at("when");Require(when.is_object(),"predicate must be an object");
    auto kind=when.at("op").get<std::string>();Require(kind=="eq"||kind=="neq"||kind=="in","predicate op must be eq/neq/in");
    Require(op.op==Op::Scalar||op.op==Op::Relative||op.op==Op::Register,
        "predicate requires a scalar/relative/register read");
    Require(op.phase==1,"predicate is entry-phase only");
    op.predicateNegate=kind=="neq";
    if(kind=="in"){const auto& values=when.at("values");Require(values.is_array()&&!values.empty()&&values.size()<=16,"predicate in values");
        for(const auto& value:values)op.predicateValues[op.predicateCount++]=U64(value);}
    else {op.predicateValues[0]=U64(when.at("value"));op.predicateCount=1;}
    op.predicateMask=when.contains("mask")?U64(when.at("mask")):~0ull;op.hasPredicate=true;
}

void AllocatePools(Generation&);

void SelectEarlyPredicate(Point& p){
    // Raw registers are immutable copies in Abi, so evaluating their predicate
    // here cannot introduce a second mutable-memory observation or TOCTOU
    // ambiguity. Matching calls still run the unchanged read program.
    for(uint32_t i=0;i<p.ops.size();++i){const auto& op=p.ops[i];
        if(op.phase==1&&op.hasPredicate&&op.base==Base::Register&&op.op==Op::Register){
            p.earlyPredicateIndex=i;break;}}
}

void CompileProbeReads(Point& p,const Json& rows,const std::unordered_map<std::string,Module>& modules,
                       uint64_t maxBytes,const std::function<void(const Json&)>& evidence){
    std::unordered_map<std::string,uint32_t> reads;uint64_t phaseBytes[2]{};
    for(const auto& read:rows){evidence(read);ReadOp op;op.id=read.at("id");Require(!op.id.empty()&&!reads.contains(op.id),"duplicate read id");
        std::string phase=read.value("phase","enter");Require(phase=="enter"||phase=="leave","probe-pair read phase must be enter/leave");
        op.phase=phase=="enter"?1:2;
        std::string base=read.at("base");bool found=false;
        if(reads.contains(base)){op.base=Base::Previous;op.index=reads.at(base);found=true;}
        for(unsigned i=0;i<RegCount&&!found;++i)if(base==RegNames[i]){op.base=Base::Register;op.index=i;found=true;}
        if(!found&&base.rfind("entry:",0)==0)for(unsigned i=0;i<RegCount&&!found;++i)if(base.substr(6)==RegNames[i]){
            Require(op.phase==2,"entry register base is leave-phase only");op.base=Base::EntryRegister;op.index=i;found=true;}
        if(!found&&base.rfind("module:",0)==0){op.base=Base::Module;op.moduleBase=modules.at(base.substr(7)).base;found=true;}
        Require(found,"probe-pair read base must be a current/entry register, module or earlier read");op.offset=U64(read.value("offset",Json(0)));
        std::string kind=read.value("op","scalar");
        if(kind=="scalar"||kind=="relative"||kind=="register"){
            op.op=kind=="scalar"?Op::Scalar:kind=="relative"?Op::Relative:Op::Register;
            op.size=U64(read.value("width",Json(8)));
            Require(op.size==1||op.size==2||op.size==4||op.size==8,"scalar width");}
        else if(kind=="block"){op.op=Op::Block;op.size=U64(read.at("size"));Require(op.size>0,"block size");}
        else if(kind=="string"){op.op=Op::CString;op.size=U64(read.at("max_bytes"));Require(op.size>=1&&op.size<=4096,"string capacity");}
        else if(kind=="array"){op.op=Op::Array;auto from=read.at("count_from").get<std::string>();
            Require(reads.contains(from),"array count must refer to an earlier read");op.countIndex=reads.at(from);
            op.stride=U64(read.at("stride"));op.maxCount=U64(read.at("max_count"));
            Require(op.stride&&op.maxCount&&op.maxCount<=UINT64_MAX/op.stride,"array overflow/empty bound");op.size=op.maxCount*op.stride;}
        else throw std::runtime_error("probe-pair v2 supports scalar/relative/register/block/string/array reads");
        if(op.op==Op::Register)Require((op.base==Base::Register||op.base==Base::EntryRegister)&&op.offset==0,
            "register read requires a current/entry register base and zero offset");
        auto dependency=[&](uint32_t index,const char* message){const auto& prior=p.ops.at(index);
            Require(prior.op==Op::Scalar||prior.op==Op::Relative||prior.op==Op::Register,message);
            Require(prior.phase==op.phase,"read dependency unavailable at selected phase");};
        if(op.base==Base::Previous)dependency(op.index,"read dependency not scalar");
        if(op.op==Op::Array)dependency(op.countIndex,"array count dependency not scalar");
        CompilePredicate(read,op);
        auto& bytes=phaseBytes[op.phase-1];Require(op.size<=maxBytes&&bytes<=maxBytes-op.size,"read program exceeds per-phase budget");bytes+=op.size;
        reads[op.id]=(uint32_t)p.ops.size();p.ops.push_back(op);
    }
    SelectEarlyPredicate(p);
    p.blobCapacity=(size_t)std::max(phaseBytes[0],phaseBytes[1]);
}

uint32_t RequirePatchContract(const Json& patch,const Bytes& prefix){
    Require(patch.is_object(),"backend patch contract required");Require(patch.at("backend_build_hash")==GumBuildHash,"backend build hash");
    auto span=U64(patch.at("required_redirect_span")),relocated=U64(patch.at("relocated_span"));
    auto redirect=patch.at("redirect_kind").get<std::string>();
    Require(((redirect=="near"&&span==5)||(redirect=="far"&&span==16))&&relocated>=span&&prefix.size()>=relocated,"backend redirect span");
    Require(patch.at("fault_in_relocated_span_test")=="passed-own-fixture","relocated-span safety not qualified");
    Require(patch.at("architectural_rsp_test")=="passed-own-fixture","architectural RSP not qualified");
    auto policy=patch.at("cet_cfg_test").get<std::string>();Require(policy=="passed-own-fixture"||policy=="target-runtime-required"||policy=="target-runtime-observed","CFG/CET contract");
    if(policy=="target-runtime-observed"){
        FILETIME created{},exited{},kernel{},user{};Require(GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)!=FALSE,"process identity query");
        ULARGE_INTEGER ticks{};ticks.LowPart=created.dwLowDateTime;ticks.HighPart=created.dwHighDateTime;
        const auto& identity=patch.at("target_process_identity");Require(U64(identity.at("pid"))==GetCurrentProcessId()&&
            U64(identity.at("creation_time_100ns"))==ticks.QuadPart,"target qualification belongs to another process instance");
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
        Require(GetProcessMitigationPolicy(GetCurrentProcess(),ProcessControlFlowGuardPolicy,&cfg,sizeof(cfg))!=FALSE&&
            GetProcessMitigationPolicy(GetCurrentProcess(),ProcessUserShadowStackPolicy,&cet,sizeof(cet))!=FALSE,"target policy query");
        const auto& observed=patch.at("target_process_policy");Require(observed.at("cfg_enabled").get<bool>()==(cfg.EnableControlFlowGuard!=0)&&
            observed.at("cet_user_shadow_stack_enabled").get<bool>()==(cet.EnableUserShadowStack!=0)&&
            observed.at("cet_user_shadow_stack_strict").get<bool>()==(cet.EnableUserShadowStackStrictMode!=0),"target policy changed after qualification");}
    return (uint32_t)span;
}
void RequireExitContract(const Json& contract){
    static constexpr const char* fields[]={"probe_semantics","return_value_stable","xmm_return_stable","stack_restored",
        "caller_return_slot_valid","stack_adjust_remaining","nonvolatile_restore_remaining","relocation_class",
        "exception_neutral_relocation","contract_evidence"};
    Require(contract.is_object()&&contract.size()==std::size(fields),"incomplete exit capture contract");
    for(auto field:fields)Require(contract.contains(field),"incomplete exit capture contract");
    Require(contract.at("probe_semantics")=="pre_instruction","exit probe semantics");
    Require(contract.at("return_value_stable").is_boolean()&&contract.at("xmm_return_stable").is_boolean(),"return stability contract");
    Require(contract.at("stack_restored").is_boolean()&&contract.at("caller_return_slot_valid").is_boolean(),"stack contract");
    U64(contract.at("stack_adjust_remaining"));Require(contract.at("nonvolatile_restore_remaining").is_array(),"restore contract");
    Require(contract.at("contract_evidence").is_array()&&!contract.at("contract_evidence").empty(),"contract evidence");
}

void RequireCallerContinuationContract(const Json& site,uint64_t returnRva){
    const auto& source=site.at("source_contract");
    Require(source.at("instruction_boundary_verified_by")=="capstone"&&
        source.at("predecessor_call_ends_at_return_rva")==true&&
        source.at("relocation_window_instruction_complete")==true&&
        source.at("direct_interior_edge_free")==true,"incomplete continuation source contract");
    auto semantic=U64(source.at("semantic_safe_span"));Require(semantic>=16,"continuation semantic safe span");
    const auto& call=site.at("predecessor_call");auto callsite=U64(call.at("callsite_rva")),size=U64(call.at("instruction_size"));
    Require(size&&callsite<=UINT64_MAX-size&&callsite+size==returnRva,"predecessor call does not end at continuation");
    auto bytes=Unhex(call.at("instruction_bytes"));Require(bytes.size()==size,"predecessor call byte length");
    auto kind=call.at("call_kind").get<std::string>();Require(kind=="direct"||kind=="indirect","predecessor call kind");
    const auto& capture=site.at("capture_contract");
    Require(capture.at("probe_semantics")=="pre_instruction"&&
        capture.at("completion_semantics")=="normal_return_to_observed_callsite_continuation"&&
        capture.at("same_thread_pairing")==true&&capture.at("exceptional_exit_observed")==false&&
        capture.at("return_value_stable")==true&&capture.at("xmm_return_stable")==true,
        "caller continuation capture contract");
}

std::shared_ptr<Generation> CompileV2(const Json& source){
    Require(source.value("activation_status","")!="BLOCKED_PENDING_TARGET_QUALIFICATION","plan is blocked pending target-process site qualification");
    auto gen=std::make_shared<Generation>();gen->source=source;gen->planId=source.at("plan_id");Require(!gen->planId.empty(),"empty plan id");
    gen->revision=U64(source.at("plan_revision"));auto canonical=source.dump();gen->planHash=Sha(canonical.data(),canonical.size());
    const auto& sources=source.at("sources");for(auto it=sources.begin();it!=sources.end();++it)
        Require(FileSha(Utf8(it.value().at("path").get<std::string>()))==it.value().at("sha256").get<std::string>(),"evidence source hash mismatch");
    auto evidence=[&](const Json& row){Require(row.contains("evidence")&&!row.at("evidence").empty(),"missing evidence references");
        for(const auto& ref:row.at("evidence"))Require(ref.is_string()&&sources.contains(ref.get<std::string>()),"unknown evidence reference");};
    std::unordered_map<std::string,Module> modules;for(auto it=source.at("modules").begin();it!=source.at("modules").end();++it){
        auto m=ResolveModule(it.key(),it.value());modules[it.key()]=m;gen->modules.push_back(m);}
    Require(!modules.empty(),"empty module list");const auto& resources=source.at("resources");
    auto slots=U64(resources.at("event_slots_per_observation")),maxBytes=U64(resources.at("max_record_bytes"));
    Require(slots&&slots<=UINT32_MAX&&maxBytes&&maxBytes<=UINT32_MAX,"resource bounds");
    auto nesting=U64(resources.at("thread_nesting_limit")),frames=U64(resources.at("call_frames_per_function"));
    Require(nesting>0&&nesting<=256,"thread nesting limit exceeds native ledger");
    Require(frames>0&&frames<=256,"call frame budget exceeds native ledger");
    gen->threadNestingLimit=(uint32_t)nesting;gen->pairFrameLimit=(uint32_t)frames;
    const auto& policy=source.at("physical_site_policy");
    Require(policy.at("exact_site_sharing")=="share-one-listener-multiple-logical-subscriptions"&&policy.at("partial_overlap")=="reject","physical site policy");
    std::set<std::string> ids;uint64_t logical=1;
    for(const auto& observation:source.at("observations")){
        auto p=std::make_shared<Point>();p->id=observation.at("id");Require(!p->id.empty()&&ids.insert(p->id).second,"duplicate/empty observation id");
        evidence(observation);Require(observation.at("backend")=="gum_function_probe_pair","v2 backend");p->moduleAlias=observation.at("module");
        const auto& module=modules.at(p->moduleAlias);const auto& entry=observation.at("entry");auto rva=U64(entry.at("rva"));
        p->address=Add(module.base,rva);p->original=p->address;p->moduleBase=module.base;p->backend=Backend::GumProbe;p->prefix=Unhex(entry.at("expected_prefix"));
        Require(p->prefix.size()>=16&&rva<module.size&&p->prefix.size()<=module.size-rva,"v2 entry outside module/source span");
        p->requiredRedirectSpan=RequirePatchContract(entry.at("backend_patch_contract"),p->prefix);
        p->logicalIdentity=logical++;p->numericId=(uint32_t)p->logicalIdentity;p->exitRequirement=observation.at("exit_capture_requirement");
        Require(p->exitRequirement=="none"||p->exitRequirement=="completion"||p->exitRequirement=="return_value"||p->exitRequirement=="path_identity","exit requirement");
        p->mode=p->exitRequirement=="none"?PointMode::Single:PointMode::ProbePair;
        if(observation.contains("native_exit_manifest"))p->functionId=observation.at("native_exit_manifest").at("function_id");
        else {Require(p->mode==PointMode::Single,"exit capture requires a native exit manifest");
            p->functionId=observation.value("instruction_site_id",p->id);Require(!p->functionId.empty(),"instruction site id");}
        CompileProbeReads(*p,entry.value("reads",Json::array()),modules,maxBytes,evidence);
        if(p->mode==PointMode::Single)for(const auto& op:p->ops)Require(op.phase==1,"leave read requires an exit capture requirement");
        CompileRetention(*p,observation,modules,evidence);
        Json manifest;const Json* function=nullptr;
        if(observation.contains("native_exit_manifest")){const auto& manifestRef=observation.at("native_exit_manifest");auto manifestPath=Utf8(manifestRef.at("path").get<std::string>());
            Require(FileSha(manifestPath)==manifestRef.at("sha256").get<std::string>(),"native exit manifest hash mismatch");manifest=Json::parse(ReadFile(manifestPath));
            Require(manifest.at("schema")=="uc.native-exit-manifest.v1"&&
                (manifest.at("status")=="three-way-verified"||manifest.at("status")=="partially-verified"),"native exit manifest status");
            for(const auto& row:manifest.at("functions"))if(row.at("function_id").get<std::string>()==p->functionId){Require(function==nullptr,"duplicate function in exit manifest");function=&row;}
            Require(function,"function missing from exit manifest");Require(function->at("module").get<std::string>()==p->moduleAlias&&U64(function->at("entry_rva"))==rva,"manifest entry mismatch");
            for(const auto& runtime:function->at("runtime_functions")){auto role=runtime.at("runtime_function_role").get<std::string>();
                Require(role=="primary"||role=="cold_fragment"||role=="eh_funclet"||role=="thunk"||role=="unknown","runtime function role");}}
        if(p->mode==PointMode::Single)Require(!observation.contains("completion"),"entry-only observation cannot declare completion sites");
        if(p->mode==PointMode::ProbePair&&observation.contains("completion")){
            const auto& completion=observation.at("completion");Require(completion.at("mode")=="caller_continuation","unsupported completion mode");
            const auto& sites=completion.at("sites");Require(sites.is_array()&&!sites.empty()&&sites.size()<=256,
                "caller continuation sites must contain 1..256 rows");
            std::vector<uint64_t> continuationAddresses;
            for(const auto& candidate:sites){evidence(candidate);auto alias=candidate.at("module").get<std::string>();const auto& callerModule=modules.at(alias);
                auto returnRva=U64(candidate.at("return_rva"));Require(returnRva<callerModule.size,"caller continuation outside module");
                RequireCallerContinuationContract(candidate,returnRva);ExitSite site;site.id=candidate.at("id");site.moduleAlias=alias;
                site.completionSemantics="normal_return_to_observed_callsite_continuation";site.callerReturnAddress=Add(callerModule.base,returnRva);
                site.address=site.callerReturnAddress;site.prefix=Unhex(candidate.at("expected_prefix"));
                auto semantic=U64(candidate.at("source_contract").at("semantic_safe_span"));
                Require(site.prefix.size()>=16&&site.prefix.size()<=callerModule.size-returnRva&&semantic<=site.prefix.size(),
                    "caller continuation source span");
                auto patchRva=candidate.at("backend_patch_contract").value("probe_rva",Json(returnRva));
                Require(U64(patchRva)==returnRva,"caller continuation patch RVA mismatch");
                site.requiredRedirectSpan=RequirePatchContract(candidate.at("backend_patch_contract"),site.prefix);
                site.contract=candidate.at("capture_contract");continuationAddresses.push_back(site.callerReturnAddress);p->exits.push_back(std::move(site));}
            std::sort(continuationAddresses.begin(),continuationAddresses.end());
            Require(std::adjacent_find(continuationAddresses.begin(),continuationAddresses.end())==continuationAddresses.end(),
                "duplicate caller continuation");
            Require(continuationAddresses==p->exactCallerAddresses,
                "exact caller gates and continuation sites must match exactly");
        }else if(p->mode==PointMode::ProbePair){Require(function,"probe-pair function manifest missing");const auto& complete=function->at("completeness");
            Require(complete.at("normal_exit_set_complete")==true&&complete.at("cold_fragments_complete")==true,"exit/cold-fragment coverage incomplete");
            for(const auto& exit:function->at("normal_exits")){Require(exit.at("terminal_semantics")=="normal_return"&&exit.at("terminal_semantics_verified")==true,"terminal semantics not verified");
                const Json* selected=nullptr;uint64_t selectedSpan=UINT64_MAX;
                for(const auto& candidate:exit.at("probe_candidates")){if(!candidate.value("incoming_edges_complete",false))continue;
                    const auto& contract=candidate.at("exit_capture_contract");RequireExitContract(contract);
                    if(contract.at("relocation_class")!="pure_epilogue"||contract.at("exception_neutral_relocation")!=true)continue;
                    if(p->exitRequirement=="return_value"&&(!contract.at("return_value_stable").get<bool>()||!contract.at("xmm_return_stable").get<bool>()))continue;
                    if(candidate.at("backend_patch_contract").is_null())continue;auto semantic=Unhex(candidate.at("expected_bytes"));
                    if(!candidate.contains("verified_source_prefix"))continue;auto bytes=Unhex(candidate.at("verified_source_prefix"));
                    if(bytes.size()<semantic.size()||!std::equal(semantic.begin(),semantic.end(),bytes.begin()))continue;
                    try{RequirePatchContract(candidate.at("backend_patch_contract"),bytes);}catch(...){continue;}
                    auto span=U64(candidate.at("backend_patch_contract").at("required_redirect_span"));if(span<selectedSpan){selected=&candidate;selectedSpan=span;}}
                Require(selected,"no activation-safe exit candidate");ExitSite site;site.id=exit.at("exit_site_id");site.moduleAlias=p->moduleAlias;
                site.completionSemantics="normal_return_at_verified_callee_epilogue";auto exitRva=U64(selected->at("probe_rva"));
                site.prefix=Unhex(selected->at("verified_source_prefix"));
                Require(site.prefix.size()>=16&&exitRva<module.size&&site.prefix.size()<=module.size-exitRva,"v2 exit outside module/source span");
                site.address=Add(module.base,exitRva);
                site.requiredRedirectSpan=RequirePatchContract(selected->at("backend_patch_contract"),site.prefix);
                site.contract=selected->at("exit_capture_contract");p->exits.push_back(std::move(site));
            }
            Require(!p->exits.empty()&&p->exits.size()<=8,"probe-pair exit count must be 1..8");
        }
        p->poolSize=(uint32_t)slots;p->captureXmm=resources.value("capture_xmm",Json(true)).get<bool>();
        gen->bindings.push_back({{"point",p->id},{"point_numeric_id",p->numericId},{"address",p->address},{"module",module.alias},{"module_sha256",module.sha},{"module_base",module.base},{"module_size",module.size},
            {"module_load_identity",module.loadId},{"backend","gum_function_probe_pair"},{"mode",p->mode==PointMode::Single?"entry-only":"probe-pair"},
            {"resolved_native_prefix",Hex(p->prefix.data(),p->prefix.size())},{"function_id",p->functionId},{"exit_requirement",p->exitRequirement},
            {"retention",p->retention==RetentionMode::Full?Json("full"):observation.at("retention")},
            {"completion_mode",observation.contains("completion")?observation.at("completion").at("mode"):Json("callee_exit_set")}});
        gen->points.push_back(p);
    }
    Require(!gen->points.empty(),"empty observation list");
    struct Reservation {uint64_t address=0;uint32_t span=0;Bytes prefix;};std::vector<Reservation> reservations;
    auto reserve=[&](uint64_t address,uint32_t span,const Bytes& prefix){
        const auto end=Add(address,16);for(const auto& old:reservations){const auto oldEnd=Add(old.address,16);
            if(oldEnd<=address||end<=old.address)continue;
            Require(old.address==address&&old.span==span&&old.prefix==prefix,"partial/mismatched physical probe site overlap");}
        reservations.push_back({address,span,prefix});};
    for(const auto& point:gen->points){reserve(point->address,point->requiredRedirectSpan,point->prefix);
        for(const auto& exit:point->exits)reserve(exit.address,exit.requiredRedirectSpan,exit.prefix);}
    AllocatePools(*gen);
    return gen;
}
void AllocatePools(Generation& gen){
    // Validate the combined reservation before touching the allocator: a plan
    // is untrusted input and must not drive GB-scale allocations in-process.
    uint64_t reserved=0;for(const auto& p:gen.points){
        uint64_t per=sizeof(Cell);
        Require(p->blobCapacity<=(MaxPlanPreallocationBytes-per)/2,"record blob preallocation exceeds process safety budget");
        per+=2*p->blobCapacity;
        Require(p->ops.size()<=(MaxPlanPreallocationBytes-per)/(2*sizeof(ReadResult)),"read result preallocation exceeds process safety budget");
        per+=2*(uint64_t)p->ops.size()*sizeof(ReadResult);
        Require(per&&p->poolSize<=(MaxPlanPreallocationBytes-reserved)/per,"combined pool preallocation exceeds process safety budget");
        reserved+=(uint64_t)p->poolSize*per;
        Require((uint64_t)p->aggregateCapacity*sizeof(AggregateSlot)<=MaxPlanPreallocationBytes-reserved,
            "combined retention preallocation exceeds process safety budget");
        reserved+=(uint64_t)p->aggregateCapacity*sizeof(AggregateSlot);}
    for(auto& p:gen.points){p->pool=std::make_unique<Cell[]>(p->poolSize);p->freeSlots.store(p->poolSize);
        if(p->aggregateCapacity)p->aggregates=std::make_unique<AggregateSlot[]>(p->aggregateCapacity);
        for(unsigned i=0;i<p->poolSize;++i)for(auto record:{&p->pool[i].enter,&p->pool[i].leave}){
            record->reads.resize(p->ops.size());record->bytes.resize(p->blobCapacity);}}
}
}

void Loss::Note(uint64_t qpc,uint64_t lost,uint64_t knownBytes,bool unknown,LossReason reason,uint64_t occurrences){
    events.fetch_add(lost,std::memory_order_relaxed);bytes.fetch_add(knownBytes,std::memory_order_relaxed);
    if(unknown)unknownBytes.fetch_add(1,std::memory_order_relaxed);
    auto f=first.load();while(qpc<f&&!first.compare_exchange_weak(f,qpc)){}
    auto l=last.load();while(qpc>l&&!last.compare_exchange_weak(l,qpc)){}
    auto& r=reasons[(size_t)reason];r.occurrences.fetch_add(occurrences);r.events.fetch_add(lost);r.bytes.fetch_add(knownBytes);
    if(unknown)r.unknownBytes.fetch_add(1);
    f=r.first.load();while(qpc<f&&!r.first.compare_exchange_weak(f,qpc)){}
    l=r.last.load();while(qpc>l&&!r.last.compare_exchange_weak(l,qpc)){}
}
Json Loss::Snapshot(const std::string& point,uint64_t generation)const{Json grouped=Json::object();
    static constexpr const char* names[]={"record_pool_exhausted","store_backpressure","pair_frame_capacity",
        "thread_nesting_capacity","pair_payload_capacity","pair_open_failure","read_failure","truncation",
        "storage_failure","frame_termination_unknown","retention_key_unavailable","retention_key_busy","retention_capacity"};
    static_assert(std::size(names)==(size_t)LossReason::Count);
    for(size_t i=0;i<reasons.size();++i){const auto& r=reasons[i];grouped[names[i]]={{"occurrences",r.occurrences.load()},
        {"events",r.events.load()},{"known_bytes",r.bytes.load()},{"unknown_byte_incidents",r.unknownBytes.load()},
        {"first_qpc",r.first.load()==UINT64_MAX?0:r.first.load()},{"last_qpc",r.last.load()}};}
    return {
    {"point",point},{"generation",generation},{"events",events.load()},{"bytes",bytes.load()},
    {"unknown_byte_records",unknownBytes.load()},{"read_failures",readFailures.load()},{"truncated",truncated.load()},
    {"first_qpc",first.load()==UINT64_MAX?0:first.load()},{"last_qpc",last.load()},
    {"reasons",grouped},{"snapshot_atomic",false}};}
Cell* Point::Acquire(){
    // O(1) rejection when the pool is exhausted; the linear probe only runs
    // while free cells actually exist.
    uint32_t available=freeSlots.load(std::memory_order_relaxed);
    while(available&& !freeSlots.compare_exchange_weak(available,available-1,std::memory_order_acquire,std::memory_order_relaxed)){}
    if(!available)return nullptr;
    const uint32_t inUse=poolSize-(available-1);auto high=poolHighWater.load(std::memory_order_relaxed);
    while(inUse>high&&!poolHighWater.compare_exchange_weak(high,inUse,std::memory_order_relaxed)){}
    auto start=next.fetch_add(1,std::memory_order_relaxed);
    for(uint32_t i=0;i<poolSize;++i){Cell& c=pool[(start+i)%poolSize];unsigned free=0;
        if(c.state.compare_exchange_strong(free,1)){c.flags.store(0);c.readyQueued.store(0);c.readyNext=UINT32_MAX;
            c.state.store(2,std::memory_order_release);return &c;}}
    freeSlots.fetch_add(1,std::memory_order_release);
    return nullptr;}
void Point::QueueReady(Cell* cell) noexcept {
    if(!cell||cell<pool.get()||cell>=pool.get()+poolSize)return;
    uint32_t clear=0;if(!cell->readyQueued.compare_exchange_strong(clear,1,std::memory_order_acq_rel))return;
    const auto depth=readyDepth.fetch_add(1,std::memory_order_relaxed)+1;auto high=readyHighWater.load(std::memory_order_relaxed);
    while(depth>high&&!readyHighWater.compare_exchange_weak(high,depth,std::memory_order_relaxed)){};
    const uint32_t index=(uint32_t)(cell-pool.get());uint64_t prior=readyHead.load(std::memory_order_relaxed);
    for(;;){cell->readyNext=(uint32_t)prior;const uint64_t desired=(((prior>>32)+1)<<32)|index;
        if(readyHead.compare_exchange_weak(prior,desired,std::memory_order_release,std::memory_order_relaxed))break;}
}
uint32_t Point::TakeReady() noexcept {
    uint64_t prior=readyHead.load(std::memory_order_acquire);
    for(;;){const uint64_t desired=(((prior>>32)+1)<<32)|UINT32_MAX;
        if(readyHead.compare_exchange_weak(prior,desired,std::memory_order_acq_rel,std::memory_order_acquire))return (uint32_t)prior;}}
bool Point::IsExactCaller(uint64_t callerAddress)const noexcept {
    return std::binary_search(exactCallerAddresses.begin(),exactCallerAddresses.end(),callerAddress);}
void Point::BreakExactCoverage(uint64_t qpc) noexcept {
    uint64_t prior=exactCoverageBrokenAt.load(std::memory_order_relaxed);
    while((!prior||qpc<prior)&&!exactCoverageBrokenAt.compare_exchange_weak(prior,qpc,std::memory_order_relaxed)){};}
RetentionResult Point::Retain(const Abi& rawAbi,uint64_t qpc) noexcept {
    if(retention==RetentionMode::Full)return {};
    aggregateCallbacks.fetch_add(1,std::memory_order_relaxed);
    RetentionResult result;result.retain=false;result.partCount=retentionKeyPartCount;
    uint64_t caller=0;
    if(!(rawAbi.registerMask&(1U<<Rsp))||!rawAbi.regs[Rsp]||!Read(rawAbi.regs[Rsp],&caller,sizeof(caller))||!caller){
        BreakExactCoverage(qpc);loss.Note(qpc,1,0,true,LossReason::RetentionKeyUnavailable);return result;}
    result.entryReturnAddress=caller;
    for(uint32_t i=0;i<retentionKeyPartCount;++i){const auto& spec=retentionKeyParts[i];uint64_t value=0;
        if(spec.kind==RetentionKeyKind::EntryReturnAddress)value=caller;
        else {if(!(rawAbi.registerMask&(1U<<spec.registerIndex))){BreakExactCoverage(qpc);
                loss.Note(qpc,1,0,true,LossReason::RetentionKeyUnavailable);return result;}
            value=rawAbi.regs[spec.registerIndex];}
        result.parts[i]=value&spec.mask;}
    // Fixed-capacity open addressing: no allocation or lock is permitted in a
    // target callback. The table size is compiler-enforced to a power of two.
    uint64_t hash=0x9e3779b97f4a7c15ULL;
    for(uint32_t i=0;i<result.partCount;++i){uint64_t value=result.parts[i]+0x9e3779b97f4a7c15ULL+(hash<<6)+(hash>>2);
        value^=value>>33;value*=0xff51afd7ed558ccdULL;value^=value>>33;hash^=value;}
    constexpr uint64_t Publishing=1;
    if(hash<=Publishing)hash=0xd6e8feb86659fd93ULL;result.hash=hash;
    const uint32_t loadLimit=std::max<uint32_t>(1,(aggregateCapacity*3+3)/4);
    for(uint32_t retry=0;;++retry){bool restart=false;
    for(uint32_t probe=0;probe<aggregateCapacity;++probe){auto& slot=aggregates[(hash+probe)&(aggregateCapacity-1)];
        uint64_t observed=slot.fingerprint.load(std::memory_order_acquire);bool first=false;
        if(observed==Publishing){restart=true;break;}
        if(!observed){
            if(aggregateKeys.load(std::memory_order_relaxed)>=loadLimit){
                BreakExactCoverage(qpc);loss.Note(qpc,1,0,true,LossReason::RetentionCapacity);return result;}
            uint64_t empty=0;if(slot.fingerprint.compare_exchange_strong(empty,Publishing,std::memory_order_acq_rel)){
                first=true;slot.partCount.store(result.partCount,std::memory_order_relaxed);
                for(uint32_t i=0;i<result.partCount;++i)slot.parts[i].store(result.parts[i],std::memory_order_relaxed);
                slot.ready.store(1,std::memory_order_relaxed);slot.fingerprint.store(hash,std::memory_order_release);
                aggregateKeys.fetch_add(1,std::memory_order_relaxed);observed=hash;}
            else {observed=empty;if(observed==Publishing){restart=true;break;}}}
        if(first||observed==hash){
            // Observing the real fingerprint with acquire also observes every
            // immutable key part published before it; ready is diagnostic only.
            bool same=slot.partCount.load(std::memory_order_relaxed)==result.partCount;
            for(uint32_t i=0;i<result.partCount&&same;++i)same=slot.parts[i].load(std::memory_order_relaxed)==result.parts[i];
            if(!same)continue;
            slot.count.fetch_add(1,std::memory_order_relaxed);
            auto f=slot.first.load(std::memory_order_relaxed);while(qpc<f&&!slot.first.compare_exchange_weak(f,qpc)){}
            auto l=slot.last.load(std::memory_order_relaxed);while(qpc>l&&!slot.last.compare_exchange_weak(l,qpc)){}
            if(!first)aggregateDuplicates.fetch_add(1,std::memory_order_relaxed);
            const bool exact=IsExactCaller(caller);result.slot=&slot;result.exact=exact;
            if(exact){aggregateExactCallbacks.fetch_add(1,std::memory_order_relaxed);result.retain=true;return result;}
            uint32_t missing=0;const bool claim=slot.sampleState.compare_exchange_strong(missing,1,std::memory_order_acq_rel);
            if(!claim)aggregateSuppressed.fetch_add(1,std::memory_order_relaxed);
            result.retain=claim;return result;}}
        if(!restart){BreakExactCoverage(qpc);loss.Note(qpc,1,0,true,LossReason::RetentionCapacity);return result;}
        // An initializer performs only fixed atomic stores. Briefly retry the
        // probe sequence so its normal publication window is not evidence
        // loss; a genuinely stalled publisher remains a bounded, explicit gap.
        if(retry>=1023){BreakExactCoverage(qpc);loss.Note(qpc,1,0,true,LossReason::RetentionKeyBusy);return result;}
        YieldProcessor();
    }}
std::shared_ptr<Generation> Compile(const Json& source,const std::function<uint64_t(uint64_t)>& slotResolver){
    std::function<void(const Json&)> numbers=[&](const Json& value){Require(!value.is_number_float(),"CapturePlan uses integer bit patterns, not floating JSON numbers");
        if(value.is_structured())for(const auto& child:value)numbers(child);};numbers(source);
    if(source.at("schema")=="uc.capture-plan.v2")return CompileV2(source);
    Require(source.at("schema")=="uc.capture-plan.v1","plan schema");auto gen=std::make_shared<Generation>();gen->source=source;
    gen->planId=source.at("plan_id");Require(!gen->planId.empty(),"empty plan id");gen->revision=U64(source.at("plan_revision"));
    auto canonical=source.dump();gen->planHash=Sha(canonical.data(),canonical.size());
    const auto& sources=source.at("sources");for(auto it=sources.begin();it!=sources.end();++it){
        Require(FileSha(Utf8(it.value().at("path").get<std::string>()))==it.value().at("sha256").get<std::string>(),"evidence source hash mismatch");}
    auto evidence=[&](const Json& row){Require(row.contains("evidence")&&!row.at("evidence").empty(),"missing evidence references");
        for(const auto& ref:row.at("evidence"))Require(ref.is_string()&&sources.contains(ref.get<std::string>()),"unknown evidence reference");};
    std::unordered_map<std::string,Module> modules;
    for(auto it=source.at("modules").begin();it!=source.at("modules").end();++it){auto m=ResolveModule(it.key(),it.value());modules[it.key()]=m;gen->modules.push_back(m);}
    Require(!modules.empty(),"empty module list");auto slots=U64(source.at("resources").at("slots_per_point"));
    auto maxBytes=U64(source.at("resources").at("max_record_bytes"));Require(slots>0&&slots<=UINT32_MAX&&maxBytes>0&&maxBytes<=UINT32_MAX,"resource bounds");
    std::set<std::string> ids;
    for(const auto& item:source.at("points")){
        auto p=std::make_shared<Point>();p->id=item.at("id");Require(!p->id.empty()&&ids.insert(p->id).second,"duplicate/empty point id");
        p->numericId=(uint32_t)gen->points.size()+1;
        evidence(item);p->moduleAlias=item.at("module");const auto& m=modules.at(p->moduleAlias);auto rva=U64(item.at("rva"));Require(rva<m.size,"point outside module");
        p->address=Add(m.base,rva);p->moduleBase=m.base;
        std::string backend=item.at("backend");p->backend=backend=="slot"?Backend::Slot:Backend::GumProbe;
        Require(backend=="slot"||backend=="gum_probe","unknown backend");
        p->abi=item.value("abi","");
        if(p->backend==Backend::Slot){const auto& target=modules.at(item.at("target_module"));
            if(item.value("target_resolution","")=="live-slot"){
                Require(!!slotResolver,"live slot needs owned-pointer-aware resolver");p->original=slotResolver(p->address);
                Require(p->original>=target.base&&p->original-target.base<target.size,"live slot target not in verified target module");
            }else {auto at=U64(item.at("target_rva"));Require(at<target.size,"slot target outside module");p->original=Add(target.base,at);}
            Require(p->address%8==0,"unaligned data slot");
            if(item.contains("expected_prefix_from_module_file")){auto size=U64(item.at("expected_prefix_from_module_file"));
                Require(size>=16&&size<=256,"module file prefix size");p->prefix=ModuleFilePrefix(target,p->original-target.base,(size_t)size);}
        }else p->original=p->address;
        if(p->prefix.empty())p->prefix=Unhex(item.at("expected_prefix"));Require(!p->prefix.empty(),"empty expected prefix");
        for(const auto& prior:gen->points)if(prior->address==p->address){
            const bool exact=prior->prefix==p->prefix&&prior->backend==p->backend&&prior->abi==p->abi;
            Require(exact,"mismatched observations target the same physical location");
            Require(p->backend==Backend::GumProbe,"only instruction probes support logical sharing in capture-plan.v1");
        }
        Bytes prefix(p->prefix.size());Require(Read(p->original,prefix.data(),prefix.size()),"target unreadable");
        // Existing owned hooks are checked by Runtime against their saved pre-install prefix.
        std::unordered_map<std::string,uint32_t> reads;
        for(const auto& read:item.value("reads",Json::array())){
            evidence(read);ReadOp op;op.id=read.at("id");Require(!op.id.empty()&&!reads.contains(op.id),"duplicate read id");
            std::string base=read.at("base");bool found=false;
            if(reads.contains(base)){op.base=Base::Previous;op.index=reads.at(base);found=true;}
            for(unsigned i=0;i<RegCount&&!found;++i)if(base==RegNames[i]){
                Require(p->backend!=Backend::Slot,"legacy backend does not provide raw CPU registers");op.base=Base::Register;op.index=i;found=true;}
            if(!found&&base.size()==4&&base.substr(0,3)=="arg"&&base[3]>='0'&&base[3]<='7'){
                Require(!p->abi.empty()&&p->backend==Backend::Slot,"this backend does not expose verified semantic arguments");op.base=Base::Argument;op.index=base[3]-'0';found=true;}
            if(!found&&base.rfind("module:",0)==0){op.base=Base::Module;op.moduleBase=modules.at(base.substr(7)).base;found=true;}
            Require(found,"unknown or forward read base");op.offset=U64(read.value("offset",Json(0)));
            std::string phase=read.value("phase","both");Require(phase=="enter"||phase=="leave"||phase=="both","read phase");
            op.phase=phase=="enter"?1:phase=="leave"?2:3;Require(p->backend!=Backend::GumProbe||op.phase==1,"probe has no leave");
            std::string kind=read.value("op","scalar");
            if(kind=="scalar"||kind=="relative"||kind=="register"){
                op.op=kind=="scalar"?Op::Scalar:kind=="relative"?Op::Relative:Op::Register;
                op.size=U64(read.value("width",Json(8)));
                Require(op.size==1||op.size==2||op.size==4||op.size==8,"scalar width");}
            else if(kind=="block"){op.op=Op::Block;op.size=U64(read.at("size"));Require(op.size>0,"block size");}
            else if(kind=="string"){op.op=Op::CString;op.size=U64(read.at("max_bytes"));Require(op.size>=1&&op.size<=4096,"string capacity");}
            else if(kind=="array"){op.op=Op::Array;op.countIndex=reads.at(read.at("count_from"));op.stride=U64(read.at("stride"));
                op.maxCount=U64(read.at("max_count"));Require(op.stride&&op.maxCount&&op.maxCount<=UINT64_MAX/op.stride,"array overflow/empty bound");op.size=op.maxCount*op.stride;}
            else throw std::runtime_error("unsupported read operation");
            if(op.op==Op::Register)Require(op.base==Base::Register&&op.offset==0,
                "register read requires a raw register base and zero offset");
            auto dependency=[&](uint32_t i){const auto& prior=p->ops.at(i);
                Require(prior.op==Op::Scalar||prior.op==Op::Relative||prior.op==Op::Register,
                    "read dependency is not a scalar value");
                Require((prior.phase&op.phase)==op.phase,"read dependency unavailable at selected phase");};
            if(op.base==Base::Previous)dependency(op.index);if(op.op==Op::Array)dependency(op.countIndex);
            CompilePredicate(read,op);
            Require(op.size<=maxBytes&&p->blobCapacity<=maxBytes-op.size,"read program exceeds budget");p->blobCapacity+=(size_t)op.size;
            reads[op.id]=(uint32_t)p->ops.size();p->ops.push_back(op);
        }
        SelectEarlyPredicate(*p);
        if(item.contains("legacy_reader"))evidence(item.at("legacy_reader"));ConfigureLegacy(*p,item,modules);
        Require(p->blobCapacity<=maxBytes,"frozen reader exceeds record byte budget");
        CompileRetention(*p,item,modules,evidence);
        p->poolSize=(uint32_t)slots;p->captureXmm=source.at("resources").value("capture_xmm",Json(true)).get<bool>();
        gen->bindings.push_back({{"point",p->id},{"point_numeric_id",p->numericId},{"address",p->address},{"target",p->original},{"module",m.alias},
            {"module_sha256",m.sha},{"module_base",m.base},{"module_size",m.size},{"module_load_identity",m.loadId},{"backend",backend},
            {"retention",p->retention==RetentionMode::Full?Json("full"):item.at("retention")},
            {"resolved_native_prefix",Hex(p->prefix.data(),p->prefix.size())},{"target_resolution",item.value("target_resolution","fixed-rva")}});
        gen->points.push_back(p);
    }
    Require(!gen->points.empty(),"empty observation list");
    AllocatePools(*gen);
    return gen;
}
namespace {
// NUL-terminated bounded read. Walks in validated chunks and falls back to a
// byte-wise probe at a page boundary, so a string that ends near the last
// valid byte still captures instead of failing the whole region.
bool ReadCString(uint64_t address,unsigned char* dst,uint64_t capacity,uint64_t& length,bool& terminated) noexcept {
    length=0;terminated=false;
    while(length<capacity&&!terminated){
        if(length>UINT64_MAX-address)return false;
        const uint64_t current=address+length;
        uint64_t want=std::min<uint64_t>(64,capacity-length);
        if(Read(current,dst+length,(size_t)want)){
            for(uint64_t i=0;i<want;++i)if(dst[length+i]==0){length+=i;terminated=true;break;}
            if(!terminated)length+=want;
            continue;}
        for(uint64_t i=0;i<want;++i){
            if(i>UINT64_MAX-current||!Read(current+i,dst+length+i,1))return false; // unreadable before NUL: capture fails honestly
            if(dst[length+i]==0){length+=i;terminated=true;break;}
            if(i==want-1)length+=want;}
    }
    return true;
}
}
bool RejectByEarlyPredicate(Point& point,const Abi& now) noexcept {
    if(point.earlyPredicateIndex==UINT32_MAX)return false;
    const auto begin=Clock();const auto& op=point.ops[point.earlyPredicateIndex];uint64_t base=0,value=0;
    if(op.base!=Base::Register||op.op!=Op::Register||!(now.registerMask&(1U<<op.index)))return false;
    base=now.regs[op.index];value=base;if(op.size<8)value&=(1ull<<(op.size*8))-1;
    bool equal=false;for(uint32_t n=0;n<op.predicateCount;++n)
        equal|=(value&op.predicateMask)==(op.predicateValues[n]&op.predicateMask);
    if(equal!=op.predicateNegate)return false;
    const auto end=Clock(),ticks=end-begin;point.filtered.fetch_add(1,std::memory_order_relaxed);
    point.earlyFiltered.fetch_add(1,std::memory_order_relaxed);
    point.readSamples.fetch_add(1,std::memory_order_relaxed);point.readTicks.fetch_add(ticks,std::memory_order_relaxed);
    auto maximum=point.readMax.load(std::memory_order_relaxed);
    while(ticks>maximum&&!point.readMax.compare_exchange_weak(maximum,ticks,std::memory_order_relaxed)){}
    return true;
}
bool Capture(Point& point,Record& record,const Abi& now,const Abi& entry,uint32_t phase) noexcept {
    record.abi=now;if(!point.captureXmm)record.abi.xmmMask=0;
    record.used=0;record.qpc=Clock();record.tid=GetCurrentThreadId();record.exceptional=false;
    auto note=[&](uint64_t lost,uint64_t bytes,bool unknown,LossReason reason){
        if(point.retention==RetentionMode::Full||record.retentionExact)point.BreakExactCoverage(record.qpc);
        point.loss.Note(record.qpc,lost,bytes,unknown,reason);};
    auto finishTiming=[&](){record.endQpc=Clock();auto ticks=record.endQpc-record.qpc;
        point.readSamples.fetch_add(1,std::memory_order_relaxed);point.readTicks.fetch_add(ticks,std::memory_order_relaxed);
        auto maximum=point.readMax.load(std::memory_order_relaxed);
        while(ticks>maximum&&!point.readMax.compare_exchange_weak(maximum,ticks,std::memory_order_relaxed)){};};
    for(size_t i=0;i<point.ops.size();++i){const auto& op=point.ops[i];auto& r=record.reads[i];r={};if(!(op.phase&phase))continue;
        uint64_t base=0;bool ok=true;
        if(op.base==Base::Register){ok=(now.registerMask&(1U<<op.index))!=0;base=now.regs[op.index];}
        else if(op.base==Base::EntryRegister){ok=(entry.registerMask&(1U<<op.index))!=0;base=entry.regs[op.index];}
        else if(op.base==Base::Argument){ok=(entry.argumentMask&(1U<<op.index))!=0;base=entry.args[op.index];}
        else if(op.base==Base::Previous){ok=record.reads[op.index].status==1;base=record.reads[op.index].value;}
        else base=op.moduleBase;
        if(!ok){r.status=2;point.loss.readFailures.fetch_add(1);note(0,0,false,LossReason::ReadFailure);continue;}
        if(base>UINT64_MAX-op.offset){r.status=5;point.loss.readFailures.fetch_add(1);note(0,0,false,LossReason::ReadFailure);continue;}
        r.address=base+op.offset;uint64_t bytes=op.size;
        if(op.op==Op::Array){const auto& c=record.reads[op.countIndex];if(c.status!=1){r.status=2;point.loss.readFailures.fetch_add(1);note(0,0,false,LossReason::ReadFailure);continue;}
            r.count=c.value;uint64_t count=std::min(c.value,op.maxCount);bytes=count*op.stride;
            if(c.value>op.maxCount){r.status=4;point.loss.truncated.fetch_add(1);
                const bool known=c.value-op.maxCount<=UINT64_MAX/op.stride;
                note(0,known?(c.value-op.maxCount)*op.stride:0,!known,LossReason::Truncation);}}
        r.begin=(uint32_t)record.used;r.bytes=(uint32_t)bytes;
        if(bytes>record.bytes.size()-record.used){r.status=5;r.bytes=0;point.loss.readFailures.fetch_add(1);note(0,0,false,LossReason::ReadFailure);continue;}
        if(op.op==Op::Register){
            r.address=0;r.value=base;
            if(bytes<8)r.value&=(1ull<<(bytes*8))-1;
            std::memcpy(record.bytes.data()+record.used,&r.value,(size_t)bytes);
            if(op.hasPredicate&&phase==1){bool equal=false;for(uint32_t n=0;n<op.predicateCount;++n)
                    equal|=(r.value&op.predicateMask)==(op.predicateValues[n]&op.predicateMask);
                const bool match=equal!=op.predicateNegate;
                if(!match){r.status=6;point.filtered.fetch_add(1,std::memory_order_relaxed);finishTiming();return false;}}
            r.status=1;record.used+=(size_t)bytes;continue;}
        if(op.op==Op::CString){
            uint64_t length=0;bool terminated=false;const bool readable=ReadCString(r.address,record.bytes.data()+record.used,op.size,length,terminated);
            if(!readable){r.status=3;r.bytes=0;point.loss.readFailures.fetch_add(1);note(0,0,false,LossReason::ReadFailure);continue;}
            r.value=length;r.bytes=(uint32_t)length;record.used+=(size_t)length;
            if(!terminated){r.status=4;point.loss.truncated.fetch_add(1);
                note(0,0,true,LossReason::Truncation);}
            else r.status=1;
            continue;}
        if(!Read(r.address,record.bytes.data()+record.used,(size_t)bytes)){r.status=3;r.bytes=0;point.loss.readFailures.fetch_add(1);note(0,0,false,LossReason::ReadFailure);continue;}
        if(op.op==Op::Scalar||op.op==Op::Relative){
            std::memcpy(&r.value,record.bytes.data()+record.used,(size_t)bytes);
            // Predicates see the raw loaded bits, before relative adjustment.
            if(op.hasPredicate&&phase==1){bool equal=false;for(uint32_t n=0;n<op.predicateCount;++n)
                    equal|=(r.value&op.predicateMask)==(op.predicateValues[n]&op.predicateMask);
                const bool match=equal!=op.predicateNegate;
                if(!match){r.status=6;point.filtered.fetch_add(1,std::memory_order_relaxed);finishTiming();return false;}}
            if(op.op==Op::Relative&&r.value){if(r.value>UINT64_MAX-r.address){r.status=5;point.loss.readFailures.fetch_add(1);
                    note(0,0,false,LossReason::ReadFailure);continue;}r.value+=r.address;}}
        if(r.status!=4)r.status=1;
        record.used+=(size_t)bytes;
    }
    CaptureLegacy(point,record,entry);finishTiming();
    return true;
}
}
