#pragma once
#include "common.h"
#include <functional>
namespace uc {
enum class Backend { Slot, GumProbe };
enum class PointMode { Single, ProbePair };
enum class RetentionMode { Full, FirstPerEntryReturnAddress, FirstPerCompositeKey };
enum class RetentionKeyKind { EntryReturnAddress, Register };
constexpr uint32_t MaxRetentionKeyParts = 4;
enum class Base { Register, EntryRegister, Argument, Previous, Module };
enum class Op { Scalar, Relative, Register, Block, Array, CString };
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
    // separately from loss) unless the loaded scalar or copied register bits
    // match. Evaluated on the raw bits before any relative adjustment.
    bool hasPredicate=false,predicateNegate=false;uint32_t predicateCount=0;
    std::array<uint64_t,16> predicateValues{};uint64_t predicateMask=~0ull;
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
    uint32_t exitHookId=UINT32_MAX,retentionSlotIndex=UINT32_MAX,retentionKeyPartCount=0;
    uint64_t retentionKeyHash=0,retentionEntryReturnAddress=0;
    std::array<uint64_t,MaxRetentionKeyParts> retentionKeyParts{};bool retentionExact=false;
};
struct RetentionKeyPart {
    RetentionKeyKind kind=RetentionKeyKind::EntryReturnAddress;uint32_t registerIndex=0;uint64_t mask=~0ull;
};
struct AggregateSlot {
    // fingerprint==0 is empty and fingerprint==1 is a private publication
    // sentinel. The winner publishes all immutable raw parts before replacing
    // the sentinel with the real fingerprint. Readers can therefore never
    // mistake an ordinary publication window for an unclassified callback.
    std::atomic<uint64_t> fingerprint{0};
    std::array<std::atomic<uint64_t>,MaxRetentionKeyParts> parts{};
    std::atomic<uint32_t> ready{0},partCount{0};
    std::atomic<uint64_t> count{0},first{UINT64_MAX},last{0},fullRecords{0},persistedRecords{0};
    std::atomic<uint64_t> persistedEntries{0},persistedNormalExits{0},persistedPairs{0};
    std::atomic<uint32_t> sampleState{0}; // 0=missing, 1=callback owns attempt, 2=queued
};
struct RetentionResult {
    bool retain=true;AggregateSlot* slot=nullptr;uint64_t hash=0,entryReturnAddress=0;bool exact=false;
    uint32_t partCount=0;std::array<uint64_t,MaxRetentionKeyParts> parts{};
};
struct ExitSite {
    std::string id,moduleAlias,completionSemantics;uint64_t address=0,callerReturnAddress=0;Bytes prefix;Json contract;
    uint32_t hookId=UINT32_MAX,requiredRedirectSpan=0;void* runtimeHook=nullptr;
};
struct Cell {
    // flags: 1/2 captured enter/leave, 4/8 consumed enter/leave, 16 frame
    // complete, 32 absent normal exit, 64/128 enter/leave persisted.
    std::atomic<unsigned> state{0},flags{0}; // 0=free,1=initializing,2=active
    std::atomic<uint32_t> readyQueued{0};uint32_t readyNext=UINT32_MAX;
    Record enter,leave;
};
// Capacity failures are deliberately separate.  A full record pool, a full
// storage sealing backlog, and a full pair ledger have different remedies and
// must never be collapsed into a generic "queue overflow" bucket.
enum class LossReason { RecordPoolExhausted, StoreBackpressure, PairFrameCapacity,
    ThreadNestingCapacity, PairPayloadCapacity, PairOpenFailure, ReadFailure,
    Truncation, StorageFailure, FrameTerminationUnknown, RetentionKeyUnavailable,
    RetentionKeyBusy, RetentionCapacity, Count };
struct ReasonLoss {
    std::atomic<uint64_t> occurrences{0},events{0},bytes{0},unknownBytes{0},first{UINT64_MAX},last{0};
};
struct Loss {
    std::atomic<uint64_t> events{0},bytes{0},unknownBytes{0},readFailures{0},truncated{0};
    std::atomic<uint64_t> first{UINT64_MAX},last{0};
    std::array<ReasonLoss,(size_t)LossReason::Count> reasons;
    void Note(uint64_t qpc,uint64_t lost,uint64_t knownBytes=0,bool unknown=false,
              LossReason reason=LossReason::RecordPoolExhausted,uint64_t occurrences=1);
    Json Snapshot(const std::string&,uint64_t)const;
};
struct Point {
    std::string id,moduleAlias,abi,evidenceHash;Backend backend;
    uint64_t address=0,original=0,moduleBase=0;Bytes prefix;
    std::vector<ReadOp> ops;
    size_t blobCapacity=0;uint32_t poolSize=0,hookId=0,numericId=0;
    PointMode mode=PointMode::Single;uint64_t logicalIdentity=0;std::string functionId,exitRequirement;
    uint32_t requiredRedirectSpan=0;
    std::vector<ExitSite> exits;
    std::unique_ptr<Cell[]> pool;std::atomic<uint64_t> next{0},inFlight{0};Loss loss;
    // Semaphore for O(1) rejection when the pool is exhausted instead of an
    // O(poolSize) CAS scan per event. Owned by Acquire/worker release.
    std::atomic<uint32_t> freeSlots{0};
    // Tagged intrusive ready stack. Producers publish only indices of their
    // already-owned cells; the worker detaches complete batches in O(ready).
    std::atomic<uint64_t> readyHead{UINT32_MAX};
    std::atomic<uint32_t> readyDepth{0},readyHighWater{0};
    // Independent cumulative health counters.  They are diagnostic evidence,
    // not substitutes for event/loss records, and therefore never share the
    // ordinary record pool.
    std::atomic<uint64_t> callbacksObserved{0},recordsCaptured{0},recordsStoreAttempted{0},recordsEncoded{0};
    std::atomic<uint32_t> poolHighWater{0};
    // Deliberate predicate filtering is accounted independently from loss.
    std::atomic<uint64_t> filtered{0},earlyFiltered{0};
    // A raw-register entry predicate can be evaluated before record-pool
    // acquisition, XMM copying, return-address reads, and pairing work.  The
    // normal Capture path evaluates it again for admitted records so the raw
    // evidence format and predicate semantics remain unchanged.
    uint32_t earlyPredicateIndex=UINT32_MAX;
    // Per-plan evidence retention. GPRs are copied at callback entry; XMM is
    // copied only when this logical point retains a full record.
    bool captureXmm=true;
    RetentionMode retention=RetentionMode::Full;uint32_t aggregateCapacity=0,retentionKeyPartCount=0;
    std::array<RetentionKeyPart,MaxRetentionKeyParts> retentionKeyParts{};
    std::unique_ptr<AggregateSlot[]> aggregates;
    // Resolved only for this module load instance. CapturePlan stores these as
    // evidence-backed module-relative return addresses.
    std::vector<uint64_t> exactCallerAddresses;
    std::atomic<uint64_t> aggregateCallbacks{0},aggregateDuplicates{0},aggregateSuppressed{0},aggregateExactCallbacks{0};
    std::atomic<uint32_t> aggregateKeys{0};
    // First QPC at which an exact per-callback stream became incomplete.
    // This is independent from aggregate caller-count completeness.
    std::atomic<uint64_t> exactCoverageBrokenAt{0};
    Json lastReportedRetention; // Writer thread only.
    Json lastReportedLoss; // Writer thread only, never inspected in a callback.
    std::atomic<uint64_t> coverageBegin{0},coverageEnd{0};
    // Legacy extensions are data readers, never gameplay interpreters.
    std::string legacyReader;unsigned readerKind=0,legacyKind=0;uint64_t legacyUnity=0,legacyVtable=0;size_t legacyBytes=0;
    std::atomic<uint64_t> readSamples{0},readTicks{0},readMax{0};
    Cell* Acquire();
    void QueueReady(Cell*) noexcept;
    uint32_t TakeReady() noexcept;
    bool IsExactCaller(uint64_t callerAddress)const noexcept;
    void BreakExactCoverage(uint64_t qpc) noexcept;
    RetentionResult Retain(const Abi&,uint64_t) noexcept;
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
// Returns true only for a conclusive raw-register predicate mismatch.
bool RejectByEarlyPredicate(Point&,const Abi&) noexcept;
}
