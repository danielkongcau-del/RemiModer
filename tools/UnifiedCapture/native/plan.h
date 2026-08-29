#pragma once
#include "common.h"
#include <functional>
namespace uc {
enum class Backend { Slot, GumProbe };
enum class PointMode { Single, ProbePair };
enum class Base { Register, EntryRegister, Argument, Previous, Module };
enum class Op { Scalar, Relative, Block, Array, CString };
// Hard ceiling on combined per-point pool preallocation. A bad plan must fail
// validation, not allocate gigabytes inside the observed process.
constexpr uint64_t MaxPlanPreallocationBytes = 256ull << 20;
enum Reg { Rax,Rbx,Rcx,Rdx,Rsi,Rdi,Rbp,Rsp,R8,R9,R10,R11,R12,R13,R14,R15,Rip,RegCount };
inline const char* RegNames[]={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip"};
struct Abi {
    uint64_t regs[RegCount]{},args[8]{};
    uint32_t registerMask=0,argumentMask=0;
    unsigned char xmm[16][16]{};
    uint32_t xmmMask=0;
    uint64_t stackMarker=0;
};
struct ReadOp {
    std::string id;Base base=Base::Register;Op op=Op::Scalar;
    uint32_t index=0,phase=3;uint64_t moduleBase=0,offset=0,size=8,stride=0,maxCount=0;
    uint32_t countIndex=0;
    // Entry-phase predicate: the event is filtered (not recorded, counted
    // separately from loss) unless the loaded scalar matches. Evaluated on the
    // raw loaded bits before any relative adjustment.
    bool hasPredicate=false,predicateNegate=false;uint64_t predicateValue=0,predicateMask=~0ull;
};
struct ReadResult {
    uint64_t address=0,value=0,count=0;uint32_t begin=0,bytes=0,status=0;
    // 0=not sampled at this phase; 1=ok; 2=unavailable base; 3=read failed; 4=truncated; 5=overflow; 6=filtered by plan predicate
};
struct Record {
    uint64_t id=0,qpc=0,endQpc=0,invocation=0,parent=0;uint32_t tid=0;
    bool parentKnown=false,exceptional=false;
    Abi abi;std::vector<ReadResult> reads;Bytes bytes;size_t used=0;
    uint32_t legacyOffset=0,legacySize=0,legacyFailures=0;bool legacyTruncated=false;
    uint32_t exitHookId=UINT32_MAX;
};
struct ExitSite {
    std::string id;uint64_t address=0;Bytes prefix;Json contract;uint32_t hookId=UINT32_MAX,requiredRedirectSpan=0;void* runtimeHook=nullptr;
};
struct Cell {
    std::atomic<unsigned> state{0},flags{0}; // 0=free,1=initializing,2=active
    Record enter,leave;
};
enum class LossReason { QueueOverflow, ReadFailure, Truncation, StorageFailure, FrameTerminationUnknown, Count };
struct ReasonLoss {
    std::atomic<uint64_t> occurrences{0},events{0},bytes{0},unknownBytes{0},first{UINT64_MAX},last{0};
};
struct Loss {
    std::atomic<uint64_t> events{0},bytes{0},unknownBytes{0},readFailures{0},truncated{0};
    std::atomic<uint64_t> first{UINT64_MAX},last{0};
    std::array<ReasonLoss,(size_t)LossReason::Count> reasons;
    void Note(uint64_t qpc,uint64_t lost,uint64_t knownBytes=0,bool unknown=false,
              LossReason reason=LossReason::QueueOverflow,uint64_t occurrences=1);
    Json Snapshot(const std::string&,uint64_t)const;
};
struct Point {
    std::string id,moduleAlias,abi,evidenceHash;Backend backend;
    uint64_t address=0,original=0,moduleBase=0;Bytes prefix;
    std::vector<ReadOp> ops;
    size_t blobCapacity=0;uint32_t poolSize=0,hookId=0;
    PointMode mode=PointMode::Single;uint64_t logicalIdentity=0;std::string functionId,exitRequirement;
    uint32_t requiredRedirectSpan=0;
    std::vector<ExitSite> exits;
    std::unique_ptr<Cell[]> pool;std::atomic<uint64_t> next{0},inFlight{0};Loss loss;
    // Semaphore for O(1) rejection when the pool is exhausted instead of an
    // O(poolSize) CAS scan per event. Owned by Acquire/worker release.
    std::atomic<uint32_t> freeSlots{0};
    // Deliberate predicate filtering is accounted independently from loss.
    std::atomic<uint64_t> filtered{0};
    // Per-plan evidence retention. The raw backend context is copied before a
    // logical point is selected; false suppresses XMM from the stored record.
    bool captureXmm=true;
    Json lastReportedLoss; // Writer thread only, never inspected in a callback.
    uint64_t coverageBegin=0,coverageEnd=0;
    // Legacy extensions are data readers, never gameplay interpreters.
    std::string legacyReader;unsigned readerKind=0,legacyKind=0;uint64_t legacyUnity=0,legacyVtable=0;size_t legacyBytes=0;
    std::atomic<uint64_t> readSamples{0},readTicks{0},readMax{0};
    Cell* Acquire();
};
struct Generation {
    std::string planId,planHash;uint64_t revision=0,generation=0;
    Json source,bindings;
    std::vector<Module> modules;
    std::vector<std::shared_ptr<Point>> points;
    // Physical hook id -> logical observations. Exact physical probe sites
    // share one listener; partial overlaps are rejected by Compile/Runtime.
    std::vector<std::vector<std::shared_ptr<Point>>> byHook;
    std::atomic<uint64_t> inFlight{0};
    uint32_t pairFrameLimit=256,threadNestingLimit=256;
    // Set when forced drain reclaims incomplete paired frames; late cleanup
    // must not decrement shared counters a second time.
    std::atomic<bool> reclaimed{false};
    // Fast-path module liveness epoch (see Runtime::Begin). Refreshed in the
    // callback only when the process-wide module epoch serial changed.
    std::atomic<uint64_t> moduleVerifiedEpoch{0};
};
std::shared_ptr<Generation> Compile(const Json&,const std::function<uint64_t(uint64_t)>& slotResolver={});
// Returns false when an entry-phase predicate filtered the event; the caller
// must release the cell/payload without recording and count it as filtered.
bool Capture(Point&,Record&,const Abi&,const Abi&,uint32_t phase) noexcept;
}
