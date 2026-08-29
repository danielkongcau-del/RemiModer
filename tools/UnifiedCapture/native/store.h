#pragma once
#include "common.h"
namespace uc {
class Store {
    fs::path directory,manifest;
    std::string session;
    Bytes payload;
    uint64_t chunk=0,minId=UINT64_MAX,maxId=0,minQpc=UINT64_MAX,maxQpc=0,count=0;
    bool sealed=false;
    uint64_t eventTotal=0,storedTotal=0,rawTotal=0,flushTicks=0;
public:
    explicit Store(const fs::path& root);
    void Meta(Json);
    void Event(const Json&,const void*,size_t);
    void Flush();
    void Close(const Json& loss,const std::string& cleanup);
    std::string Id()const{return session;}
    std::string Path()const{return directory.string();}
    bool Sealed()const{return sealed;}
    Json Status()const{return {{"events_encoded",eventTotal},{"sealed_chunks",chunk},{"buffered_bytes",payload.size()},
        {"sealed_raw_payload_bytes",rawTotal},{"sealed_file_bytes",storedTotal},{"flush_ticks",flushTicks}};}
};
}
