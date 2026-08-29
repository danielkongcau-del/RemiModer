#include "store.h"
namespace uc {
static void Put(Bytes& into,const void* raw,size_t size){auto p=(const unsigned char*)raw;into.insert(into.end(),p,p+size);}
Store::Store(const fs::path& root){session=UniqueId();directory=root/fs::path(session);
    Require(fs::create_directories(directory),"session directory already exists");manifest=directory/L"session.manifest";
    Meta({{"kind","session"},{"schema","uc.session.v1"},{"session_id",session},{"pid",GetCurrentProcessId()},
          {"qpc_frequency",Frequency()},{"automatic_stop",false},{"start_qpc",Clock()}});}
void Store::Meta(Json record){auto raw=record.dump();Json envelope={{"record",record},{"sha256",Sha(raw.data(),raw.size())}};
    auto line=envelope.dump()+"\n";AppendFile(manifest,line.data(),line.size());}
void Store::Event(const Json& event,const void* blob,size_t size){Require(!sealed,"sealed evidence session");auto meta=event.dump();
    Require(meta.size()<=UINT32_MAX&&size<=UINT32_MAX,"event format size overflow");uint32_t m=(uint32_t)meta.size(),b=(uint32_t)size;
    Put(payload,&m,4);Put(payload,&b,4);Put(payload,meta.data(),m);if(b)Put(payload,blob,b);
    auto id=event.at("event_id").get<uint64_t>(),qpc=event.at("qpc").get<uint64_t>();
    minId=std::min(minId,id);maxId=std::max(maxId,id);minQpc=std::min(minQpc,qpc);maxQpc=std::max(maxQpc,qpc);++count;++eventTotal;
    if(payload.size()>=4*1024*1024)Flush();}
void Store::Flush(){if(!count)return;
    const auto began=Clock();
    Bytes stored;std::string codec="none";COMPRESSOR_HANDLE compressor=nullptr;
    if(CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF,nullptr,&compressor)){
        SIZE_T needed=0;Compress(compressor,payload.data(),payload.size(),nullptr,0,&needed);
        if(needed){stored.resize(needed);if(Compress(compressor,payload.data(),payload.size(),stored.data(),stored.size(),&needed)){
            stored.resize(needed);if(stored.size()<payload.size())codec="xpress_huff";}}
        CloseCompressor(compressor);}
    if(codec=="none")stored=payload;
    Json header={{"format_version",1},{"record_encoding","uc.record.v1"},{"session_id",session},{"chunk_id",chunk},
        {"min_event_id",minId},{"max_event_id",maxId},{"min_qpc",minQpc},{"max_qpc",maxQpc},{"event_count",count},
        {"uncompressed_size",payload.size()},{"compressed_size",stored.size()},{"compression_type",codec}};
    auto unsignedHeader=header.dump();Bytes hashed(unsignedHeader.begin(),unsignedHeader.end());Put(hashed,stored.data(),stored.size());
    header["sha256"]=Sha(hashed.data(),hashed.size());header["crc32c"]=Crc(stored.data(),stored.size());auto raw=header.dump();
    Bytes file;Put(file,"UCCHNK01",8);uint32_t hs=(uint32_t)raw.size();uint64_t ps=stored.size();Put(file,&hs,4);Put(file,&ps,8);
    Put(file,raw.data(),raw.size());Put(file,stored.data(),stored.size());char name[64];sprintf_s(name,"chunk-%08llu.ucb",chunk);
    fs::path final=directory/name,pending=directory/(std::string(name)+".partial");NewFile(pending,file.data(),file.size());
    Require(MoveFileExW(pending.c_str(),final.c_str(),MOVEFILE_WRITE_THROUGH),"chunk seal failed");
    header["kind"]="chunk";header["file"]=name;Meta(header);rawTotal+=payload.size();storedTotal+=file.size();flushTicks+=Clock()-began;
    ++chunk;count=0;payload.clear();minId=minQpc=UINT64_MAX;maxId=maxQpc=0;}
void Store::Close(const Json& loss,const std::string& cleanup){if(sealed)return;Flush();
    Meta({{"kind","session_end"},{"session_id",session},{"chunks",chunk},{"cleanup",cleanup},{"loss",loss}});sealed=true;}
}
