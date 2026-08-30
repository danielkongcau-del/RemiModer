#pragma once
#include "common.h"
#include <condition_variable>
#include <deque>
#include <thread>
namespace uc {
struct StoreBackpressure final:std::runtime_error {StoreBackpressure():std::runtime_error("storage seal backlog full"){};};
// Sealing (compress + fsync + durable rename) runs on a dedicated thread so a
// slow disk cannot stall the 1ms worker tick and overflow the event pools.
// Manifest lines are queued and appended in batches with a single fsync per
// drain; control paths force durability via FlushMeta before acknowledging.
class Store {
    static constexpr uint64_t TargetSegmentBytes=32ull<<20;
    static constexpr uint64_t MaxOutstandingSealBytes=256ull<<20;
    static constexpr uint64_t CompressionDisableBacklogBytes=64ull<<20;
    fs::path directory,manifest;
    std::string session;
    uint64_t startQpc=0;
    // Worker side only (all calls happen under Runtime's state mutex).
    Bytes payload;std::string payloadEncoding;
    uint64_t nextChunk=0,minId=UINT64_MAX,maxId=0,minQpc=UINT64_MAX,maxQpc=0,count=0;
    std::atomic<bool> sealed{false},failed{false};bool shutdown=false,closeRequested=false;
    std::atomic<uint64_t> eventAttempts{0},eventTotal{0},encodedBytes{0},eventEncodeTicks{0},eventEncodeMax{0};
    std::atomic<uint64_t> sealedChunks{0},storedTotal{0},rawTotal{0},flushTicks{0};
    std::atomic<uint64_t> storeBackpressure{0},payloadHighWater{0},outstandingHighWater{0},pendingJobsHighWater{0};
    std::atomic<uint64_t> manifestFlushes{0},manifestBytes{0},manifestFlushTicks{0};
    std::atomic<uint64_t> compressionAttempts{0},compressionBypasses{0},compressedChunks{0},rawChunks{0};
    // Events known to be lost to a seal/storage failure, for honest loss notes.
    std::atomic<uint64_t> bufferedEventsLost{0};
    std::string sealError;
    struct SealJob {uint64_t chunk=0,minId=UINT64_MAX,maxId=0,minQpc=UINT64_MAX,maxQpc=0,count=0;Bytes payload;std::string encoding;};
    mutable std::mutex sealMutex,metaMutex,metaIoMutex;std::condition_variable sealCv;
    std::deque<SealJob> pending;
    uint64_t outstandingSealBytes=0,activeSealBytes=0;
    Json closingLoss=Json::array();std::string closingCleanup;
    std::deque<std::string> metaLines;std::string chainTail=std::string(64,'0');
    std::thread sealer;
    bool EnqueueSeal(bool closing=false);
    void AppendEvent(const char* encoding,uint64_t id,uint64_t qpc,const void* metadata,size_t metadataSize,
                     const void* blob,size_t blobSize);
    void SealOne(const SealJob&);
    void RunSealer();
    void AppendMetaLine(std::string line); // fsync'd append
public:
    explicit Store(const fs::path& root);
    ~Store();
    Store(const Store&)=delete;Store& operator=(const Store&)=delete;
    void Meta(Json);            // queue only, no I/O
    void FlushMeta();           // drain queue into the manifest, one fsync
    void Event(const Json&,const void*,size_t);
    void RawEvent(uint64_t id,uint64_t qpc,const void* metadata,size_t metadataSize,const void* blob,size_t blobSize);
    void Flush();               // enqueue a seal of the buffered payload now
    void BeginClose(const Json& loss,const std::string& cleanup); // nonblocking
    void Close(const Json& loss,const std::string& cleanup);
    const std::string& Id()const noexcept{return session;}
    std::string Path()const{return directory.string();}
    bool Sealed()const{return sealed.load(std::memory_order_acquire);}
    bool SealFailedFast()const noexcept{return failed.load(std::memory_order_acquire);}
    bool SealFailed()const;
    std::string SealErrorText()const;
    uint64_t DrainBufferedEventsLost();
    Json Status()const;
};
}
