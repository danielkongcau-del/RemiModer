#include "store.h"
#include <iostream>

int wmain(int argc,wchar_t** argv){
    if(argc!=2){std::cerr<<"StoreProbe <output-directory>\n";return 2;}
    try{
        uc::Store store(argv[1]);
        std::vector<unsigned char> blob(3*1024*1024);
        uint32_t state=0x9e3779b9U;
        for(auto& byte:blob){state=state*1664525U+1013904223U;byte=(unsigned char)(state>>24);}
        for(uint64_t i=1;i<=5;++i)store.Event({{"schema","uc.event.v1"},{"event_id",i},{"qpc",i},
            {"kind","probe"},{"point","store-probe"},{"generation",1}},blob.data(),blob.size());
        store.Close(uc::Json::array(),"STOPPED_CLEAN");
        std::cout<<uc::Json{{"ok",true},{"directory",store.Path()},{"status",store.Status()}}.dump()<<std::endl;
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
