#pragma once
#include "plan.h"
#include "store.h"
#pragma warning(push)
#pragma warning(disable:4324) // SDK's intentionally aligned GumExceptorScope.
#include "frida-gum.h"
#pragma warning(pop)
#include <deque>
namespace uc {
struct Hook {
    uint32_t id=0;Backend backend=Backend::Slot;std::string abi;
    uint64_t target=0,original=0,installGeneration=0;
    size_t reservedSpan=0,patchSpan=0;
    Bytes before,sourcePrefix,installed,current;std::vector<size_t> patchOffsets;
    GumInvocationListener* listener=nullptr;
    bool owned=false,detached=false,conflict=false;std::string error;
    std::atomic<uint64_t> executing{0};void* wrapper=nullptr;
};
struct Token {
    // The callback owns its activation generation. This keeps legacy slot
    // exits and thread-local probe-pair cleanup safe across publication/seal.
    std::shared_ptr<const Generation> generation;Point* point=nullptr;Cell* cell=nullptr;
    uint64_t invocation=0,parent=0;bool parentKnown=false,probe=false;
};
class Runtime {
    std::atomic<std::shared_ptr<const Generation>> active;
    std::atomic<bool> admitting{false},stopRequested{false},forceRelease{false},terminalCallbacks{false};
    // Per-event counters on their own cache lines: they are written from every
    // callback thread and must not share a line with publication state.
    struct alignas(64) HotCounters {std::atomic<uint64_t> entrants{0},eventIds{1},callIds{1};};
    HotCounters hot;
    // Callbacks observed while admission was closed (plan switch/stop window).
    // Counted independently so "no events" cannot be mistaken for "not called".
    struct alignas(64) AdmissionCounters {std::atomic<uint64_t> drops{0},first{0},last{0};};
    AdmissionCounters admission;
    // Seal failures can lose already-encoded jobs whose point identity is no
    // longer cheaply available. Keep their exact event count independently.
    std::atomic<uint64_t> unattributedStorageLoss{0};
    mutable std::mutex stateMutex,metaMutex,errorMutex;
    std::vector<std::shared_ptr<Generation>> generations;
    Json archivedLoss=Json::array(),archivedRetention=Json::array();
    std::vector<std::unique_ptr<Hook>> hooks;
    std::deque<Json> metadata;
    std::unique_ptr<Store> store;
    GumInterceptor* interceptor=nullptr;
    uint64_t generationCounter=0,flushQpc=0,stopQpc=0;
    std::string storageError;fs::path outputRoot;
    std::string observerSha,observerPath;
    bool clean=false,forcedTerminal=false,moduleInvalid=false,closeInitiated=false,closeForced=false;uint64_t lastModuleCheck=0;
    Json lastAdmissionNote=Json(nullptr);
    void Install(Hook&,const Point&);
    void Detach(Hook&);
    Bytes OriginalPrefix(uint64_t,size_t)const;
    Bytes ExpectedPrefix(const Hook&)const;
    void WriteRecord(const Generation&,Point&,const Record&,const char*);
    void ReportLoss(const Generation&,Point&,uint64_t);
    void ReportRetention(const Generation&,Point&,uint64_t);
    static Json PointSnapshot(const Generation&,const Point&);
    static Json RetentionSnapshot(const Generation&,const Point&);
    void NoteAdmissionDrop() noexcept;
    void ReportAdmissionWindow();
    void Archive(const Generation&);
    void NewSession();
public:
    explicit Runtime(fs::path);
    Json Apply(std::shared_ptr<Generation>);
    Json QualifySites(const Json&);
    Json Status()const;
    Json Capabilities()const;
    void Begin(Hook&,const Abi&,Token&) noexcept;
    void End(Hook&,const Abi&,Token&,bool exceptional=false) noexcept;
    void Probe(Hook&,GumInvocationContext*) noexcept;
    void Tick();
    void Meta(Json);
    // Drain the in-memory metadata queue into the durable manifest; control
    // paths call this before acknowledging state transitions.
    void FlushMetaDurable();
    void Mark(const std::string&);
    void Stop(bool force=false);
    void Start();
    Json RebindPlan()const;
    uint64_t SlotOriginal(uint64_t)const;
    static Runtime* instance;
};
Abi GumAbi(GumInvocationContext*,bool captureXmm=true);
void* LegacyWrapper(Hook&);
}
