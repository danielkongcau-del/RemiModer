#include "store.h"
namespace uc {
static void Put(Bytes& into,const void* raw,size_t size){auto p=(const unsigned char*)raw;into.insert(into.end(),p,p+size);}
Store::Store(const fs::path& root){session=UniqueId();directory=root/fs::path(session);
    Require(fs::create_directories(directory),"session directory already exists");manifest=directory/L"session.manifest";
    FILETIME now{};GetSystemTimeAsFileTime(&now);ULARGE_INTEGER ticks{};ticks.LowPart=now.dwLowDateTime;ticks.HighPart=now.dwHighDateTime;
    Meta(Json{{"kind","session"},{"schema","uc.session.v1"},{"session_id",session},{"pid",GetCurrentProcessId()},
        {"qpc_frequency",Frequency()},{"automatic_stop",false},{"start_qpc",Clock()},
        {"start_unix_100ns",ticks.QuadPart-116444736000000000ull},{"start_wall_clock_utc",WallClockUtc()}});
    FlushMeta();
    sealer=std::thread([this]{RunSealer();});}
Store::~Store(){if(!Sealed()){try{Close(Json::array(),"DESTROYED_UNCLEAN");}catch(...){
        {std::lock_guard lock(sealMutex);shutdown=true;}sealCv.notify_all();}}
    if(sealer.joinable())sealer.join();}
void Store::Meta(Json record){
    // Hash-chained envelope: each line commits to its predecessor, so silent
    // deletion or reordering of sealed history is detectable offline.
    auto raw=record.dump();
    auto digest=Sha(raw.data(),raw.size());
    std::lock_guard lock(metaMutex);
    Json envelope={{"record",std::move(record)},{"sha256",digest},{"prev_sha256",chainTail}};
    metaLines.push_back(envelope.dump()+"\n");chainTail=digest;}
void Store::FlushMeta(){
    // Serialise both dequeue and physical append. Without this lock, two
    // callers could obtain consecutive hash-chain batches but append them in
    // the opposite order.
    std::lock_guard io(metaIoMutex);
    std::string all;
    {
        std::lock_guard lock(metaMutex);
        if(metaLines.empty())return;
        // Reserve before removing any queued line. An allocation failure then
        // leaves the complete batch available for a later diagnostic/flush.
        size_t total=0;for(const auto& line:metaLines){Require(line.size()<=SIZE_MAX-total,"manifest batch size overflow");total+=line.size();}
        all.reserve(total);for(const auto& line:metaLines)all+=line;
        metaLines.clear();
    }
    // One open/fsync/close for the whole batch; a physical append failure may
    // have written a prefix, so retrying the same bytes would be dishonest.
    // Poison the store and preserve that detectable tail instead.
    try{AppendMetaLine(std::move(all));}
    catch(const std::exception& e){std::lock_guard lock(sealMutex);if(sealError.empty())sealError=std::string("manifest: ")+e.what();
        failed.store(true,std::memory_order_release);throw;}}
void Store::AppendMetaLine(std::string line){
    HANDLE f=CreateFileW(manifest.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    Require(f!=INVALID_HANDLE_VALUE,"manifest open failed");
    try{DWORD written=0;const char* p=line.data();size_t remaining=line.size();
        while(remaining){DWORD n=(DWORD)std::min<size_t>(remaining,1<<20);
            Require(WriteFile(f,p,n,&written,nullptr)&&written==n,"manifest write failed");
            p+=n;remaining-=n;}
        Require(FlushFileBuffers(f),"manifest flush failed");}
    catch(...){CloseHandle(f);throw;}
    CloseHandle(f);}
void Store::Event(const Json& event,const void* blob,size_t size){
    if(Sealed()||closeRequested)throw std::runtime_error("sealed evidence session");
    if(auto error=SealErrorText();!error.empty())throw std::runtime_error("sealing failed earlier: "+error);
    // Do not grow the worker buffer while a full chunk is waiting for bounded
    // background capacity. The caller accounts this event independently.
    if(payload.size()>=4*1024*1024&&!EnqueueSeal())throw StoreBackpressure();
    auto meta=event.dump();
    Require(meta.size()<=UINT32_MAX&&size<=UINT32_MAX,"event format size overflow");uint32_t m=(uint32_t)meta.size(),b=(uint32_t)size;
    auto id=event.at("event_id").get<uint64_t>(),qpc=event.at("qpc").get<uint64_t>();
    const uint64_t required=8ull+m+b;Require(required<=SIZE_MAX-payload.size(),"event buffer size overflow");
    // Reserve before the first mutation. A failed allocation cannot leave a
    // partial record that would corrupt every later record in this chunk.
    payload.reserve(payload.size()+(size_t)required);
    Put(payload,&m,4);Put(payload,&b,4);Put(payload,meta.data(),m);if(b)Put(payload,blob,b);
    minId=std::min(minId,id);maxId=std::max(maxId,id);minQpc=std::min(minQpc,qpc);maxQpc=std::max(maxQpc,qpc);++count;++eventTotal;
    if(payload.size()>=4*1024*1024)EnqueueSeal();}
bool Store::EnqueueSeal(bool closing) {
    if(!count)return true;
    // Reserve the immutable chunk id at enqueue time. The sealer may lag by
    // several jobs; assigning ids on completion would give queued jobs the
    // same filename.
    {
        std::lock_guard lock(sealMutex);const uint64_t bytes=payload.size();
        if(!sealError.empty())throw std::runtime_error("sealing failed earlier: "+sealError);
        Require(!shutdown,"sealer already stopped");
        // Capture-time enqueue never waits. The worker retains its current
        // chunk and later events are loss-accounted as queue overflow. Closing
        // may add one final bounded chunk beyond the steady-state ceiling.
        if(!closing&&(bytes>MaxOutstandingSealBytes||
            outstandingSealBytes>MaxOutstandingSealBytes-bytes))return false;
        // Allocate the deque node before moving the only copy of the payload.
        // If allocation throws, every event and counter remains on the worker
        // side and a later stop can still report the failure honestly.
        pending.emplace_back();auto& job=pending.back();
        job.chunk=nextChunk++;job.minId=minId;job.maxId=maxId;job.minQpc=minQpc;job.maxQpc=maxQpc;job.count=count;
        job.payload.swap(payload);outstandingSealBytes+=bytes;
    }
    count=0;minId=minQpc=UINT64_MAX;maxId=maxQpc=0;sealCv.notify_one();return true;}
void Store::Flush(){if(!Sealed()&&!closeRequested){if(auto error=SealErrorText();!error.empty())throw std::runtime_error("sealing failed earlier: "+error);EnqueueSeal();}}
void Store::SealOne(const SealJob& job){
    const auto began=Clock();
    Bytes stored;std::string codec="none";COMPRESSOR_HANDLE compressor=nullptr;
    if(CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF,nullptr,&compressor)){
        SIZE_T needed=0;Compress(compressor,job.payload.data(),job.payload.size(),nullptr,0,&needed);
        if(needed){stored.resize(needed);if(Compress(compressor,job.payload.data(),job.payload.size(),stored.data(),stored.size(),&needed)){
            stored.resize(needed);if(stored.size()<job.payload.size())codec="xpress_huff";}}
        CloseCompressor(compressor);}
    if(codec=="none")stored=job.payload;
    Json header={{"format_version",1},{"record_encoding","uc.record.v1"},{"session_id",session},{"chunk_id",job.chunk},
        {"min_event_id",job.minId},{"max_event_id",job.maxId},{"min_qpc",job.minQpc},{"max_qpc",job.maxQpc},{"event_count",job.count},
        {"uncompressed_size",job.payload.size()},{"compressed_size",stored.size()},{"compression_type",codec}};
    auto unsignedHeader=header.dump();Bytes hashed(unsignedHeader.begin(),unsignedHeader.end());Put(hashed,stored.data(),stored.size());
    header["sha256"]=Sha(hashed.data(),hashed.size());header["crc32c"]=Crc(stored.data(),stored.size());auto raw=header.dump();
    Bytes file;Put(file,"UCCHNK01",8);uint32_t hs=(uint32_t)raw.size();uint64_t ps=stored.size();Put(file,&hs,4);Put(file,&ps,8);
    Put(file,raw.data(),raw.size());Put(file,stored.data(),stored.size());char name[64];sprintf_s(name,"chunk-%08llu.ucb",job.chunk);
    fs::path final=directory/name,partial=directory/(std::string(name)+".partial");NewFile(partial,file.data(),file.size());
    Require(MoveFileExW(partial.c_str(),final.c_str(),MOVEFILE_WRITE_THROUGH),"chunk seal failed");
    header["kind"]="chunk";header["file"]=name;Meta(std::move(header));FlushMeta();
    rawTotal+=job.payload.size();storedTotal+=file.size();flushTicks+=Clock()-began;sealedChunks.fetch_add(1);}
void Store::RunSealer(){
    for(;;){SealJob job;bool has=false;
        {std::unique_lock lock(sealMutex);sealCv.wait(lock,[this]{return shutdown||!pending.empty();});
            if(pending.empty()&&shutdown){if(!closeRequested)return;lock.unlock();
                try{FlushMeta();Meta(Json{{"kind","session_end"},{"session_id",session},{"chunks",sealedChunks.load()},
                    {"cleanup",closingCleanup},{"loss",closingLoss}});FlushMeta();sealed.store(true,std::memory_order_release);}
                catch(const std::exception& e){std::lock_guard failedLock(sealMutex);if(sealError.empty())sealError=e.what();
                    failed.store(true,std::memory_order_release);}
                sealCv.notify_all();return;}
            job=std::move(pending.front());pending.pop_front();activeSealBytes=job.payload.size();has=true;}
        (void)has;
        try{SealOne(job);{std::lock_guard lock(sealMutex);outstandingSealBytes-=job.payload.size();activeSealBytes=0;}sealCv.notify_all();}
        catch(const std::exception& e){
            // First failure poisons the store: remaining queued payloads are
            // known-lost, counted, and surfaced instead of silently dropped.
            uint64_t lost=job.count;std::deque<SealJob> drain;
            {std::lock_guard lock(sealMutex);if(sealError.empty())sealError=e.what();
                failed.store(true,std::memory_order_release);drain.swap(pending);outstandingSealBytes=0;activeSealBytes=0;}
            for(const auto& other:drain)lost+=other.count;
            bufferedEventsLost.fetch_add(lost);sealCv.notify_all();
            return;}}}
void Store::BeginClose(const Json& loss,const std::string& cleanup){
    if(Sealed()||closeRequested)return;
    if(auto error=SealErrorText();!error.empty()){
        // Events accumulated on the worker while the asynchronous failure was
        // still propagating are now known-unsealable too.
        bufferedEventsLost.fetch_add(count);count=0;payload.clear();minId=minQpc=UINT64_MAX;maxId=maxQpc=0;
        throw std::runtime_error("sealing failed earlier: "+error);}
    // Prepare final metadata before publishing any close state. Allocation
    // failure leaves the live session and worker payload unchanged.
    Json preparedLoss=loss;std::string preparedCleanup=cleanup;
    // Queue the final payload while the sealer is alive, then let that same
    // thread append session_end after every chunk manifest is durable.
    EnqueueSeal(true);
    {std::lock_guard lock(sealMutex);closingLoss=std::move(preparedLoss);closingCleanup=std::move(preparedCleanup);closeRequested=true;shutdown=true;}
    sealCv.notify_all();}
void Store::Close(const Json& loss,const std::string& cleanup){
    BeginClose(loss,cleanup);
    std::unique_lock lock(sealMutex);sealCv.wait(lock,[this]{return sealed.load()||!sealError.empty();});
    auto error=sealError;lock.unlock();
    if(!error.empty())throw std::runtime_error("sealing failed earlier: "+error);
    if(sealer.joinable()&&sealer.get_id()!=std::this_thread::get_id())sealer.join();}
bool Store::SealFailed()const{std::lock_guard lock(sealMutex);return !sealError.empty();}
std::string Store::SealErrorText()const{std::lock_guard lock(sealMutex);return sealError;}
uint64_t Store::DrainBufferedEventsLost(){uint64_t lost=bufferedEventsLost.exchange(0);
    if(SealFailed()&&count){lost+=count;count=0;payload.clear();minId=minQpc=UINT64_MAX;maxId=maxQpc=0;}return lost;}
Json Store::Status()const{std::lock_guard lock(sealMutex);uint64_t pendingBytes=0;for(const auto& job:pending)pendingBytes+=job.payload.size();
    return {{"events_encoded",eventTotal.load()},{"sealed_chunks",sealedChunks.load()},
        {"buffered_bytes",payload.size()},{"pending_seal_jobs",pending.size()},{"pending_seal_bytes",pendingBytes},
        {"active_seal_bytes",activeSealBytes},{"outstanding_seal_bytes",outstandingSealBytes},
        {"max_outstanding_seal_bytes",MaxOutstandingSealBytes},
        {"sealed_raw_payload_bytes",rawTotal.load()},{"sealed_file_bytes",storedTotal.load()},{"flush_ticks",flushTicks.load()},
        {"seal_error",sealError}};}
}
