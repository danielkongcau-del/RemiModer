#include "common.h"
#include "modules.h"
#include <sstream>

namespace uc {
std::string Hex(const void* raw,size_t size) {
    static constexpr char digits[]="0123456789abcdef";
    std::string out(size*2,'0');auto p=static_cast<const unsigned char*>(raw);
    for(size_t i=0;i<size;++i){out[2*i]=digits[p[i]>>4];out[2*i+1]=digits[p[i]&15];}return out;
}
Bytes Unhex(const std::string& value) {
    Require(value.size()%2==0,"odd hex string");Bytes out(value.size()/2);
    auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;
        if(c>='A'&&c<='F')return c-'A'+10;throw std::runtime_error("invalid hex");};
    for(size_t i=0;i<out.size();++i)out[i]=(unsigned char)(digit(value[2*i])*16+digit(value[2*i+1]));return out;
}
class Hasher {
    BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
public:
    Hasher(){Require(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,"SHA provider");
        if(BCryptCreateHash(algorithm,&hash,nullptr,0,nullptr,0,0)<0){BCryptCloseAlgorithmProvider(algorithm,0);throw std::runtime_error("SHA create");}}
    ~Hasher(){if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);}
    void add(const void* data,size_t bytes){auto p=(const unsigned char*)data;while(bytes){ULONG n=(ULONG)std::min<size_t>(bytes,1<<20);
        Require(BCryptHashData(hash,const_cast<PUCHAR>(p),n,0)>=0,"SHA update");p+=n;bytes-=n;}}
    std::string finish(){unsigned char out[32];Require(BCryptFinishHash(hash,out,32,0)>=0,"SHA finish");return Hex(out,32);}
};
std::string Sha(const void* data,size_t size){Hasher h;h.add(data,size);return h.finish();}
std::string FileSha(const fs::path& path){std::ifstream f(path,std::ios::binary);Require(!!f,"hash source missing");
    Hasher h;std::vector<char> bytes(1<<20);while(f){f.read(bytes.data(),bytes.size());h.add(bytes.data(),(size_t)f.gcount());}
    Require(f.eof(),"hash source read failed");return h.finish();}
uint32_t Crc(const void* data,size_t size){
    static const auto table=[](){std::array<uint32_t,256> t{};for(unsigned i=0;i<256;++i){uint32_t c=i;
        for(unsigned n=0;n<8;++n)c=(c>>1)^((c&1)?0x82f63b78U:0);t[i]=c;}return t;}();
    uint32_t c=~0U;auto p=(const unsigned char*)data;for(size_t i=0;i<size;++i)c=(c>>8)^table[(c^p[i])&255];return ~c;
}
static bool Copy(uint64_t address,void* output,size_t size) noexcept {
    __try {std::memcpy(output,(const void*)(uintptr_t)address,size);return true;}
    __except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION||GetExceptionCode()==EXCEPTION_IN_PAGE_ERROR?
             EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){return false;}
}
bool Read(uint64_t address,void* output,size_t size) noexcept {
    if(!size)return true;if(!address||address>UINT64_MAX-size)return false;
    uint64_t cursor=address,end=address+size;while(cursor<end){MEMORY_BASIC_INFORMATION m{};
        if(!VirtualQuery((void*)(uintptr_t)cursor,&m,sizeof(m))||m.State!=MEM_COMMIT||(m.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
        unsigned p=m.Protect&255;if(p!=PAGE_READONLY&&p!=PAGE_READWRITE&&p!=PAGE_WRITECOPY&&p!=PAGE_EXECUTE_READ&&p!=PAGE_EXECUTE_READWRITE&&p!=PAGE_EXECUTE_WRITECOPY)return false;
        uint64_t next=(uint64_t)m.BaseAddress+m.RegionSize;if(next<=cursor)return false;cursor=next;}
    return Copy(address,output,size);
}
Bytes ReadFile(const fs::path& path){std::ifstream f(path,std::ios::binary|std::ios::ate);Require(!!f,"file unavailable");
    auto size=f.tellg();Require(size>=0,"file size");Bytes out((size_t)size);f.seekg(0);f.read((char*)out.data(),out.size());Require(!!f,"file read");return out;}
static void WriteHandle(HANDLE f,const void* data,size_t size){auto p=(const unsigned char*)data;while(size){DWORD n=(DWORD)std::min<size_t>(size,1<<20),done=0;
    Require(WriteFile(f,p,n,&done,nullptr)&&done==n,"storage write failed");p+=n;size-=n;}}
void NewFile(const fs::path& path,const void* data,size_t size){HANDLE f=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    Require(f!=INVALID_HANDLE_VALUE,"new evidence file already exists or cannot open");try{WriteHandle(f,data,size);Require(FlushFileBuffers(f),"storage flush failed");}
    catch(...){CloseHandle(f);throw;}CloseHandle(f);}
void AppendFile(const fs::path& path,const void* data,size_t size){HANDLE f=CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    Require(f!=INVALID_HANDLE_VALUE,"manifest open failed");try{WriteHandle(f,data,size);Require(FlushFileBuffers(f),"manifest flush failed");}
    catch(...){CloseHandle(f);throw;}CloseHandle(f);}
std::string UniqueId(){unsigned char raw[16];Require(BCryptGenRandom(nullptr,raw,16,BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0,"session randomness");return Hex(raw,16);}
Module ResolveModule(const std::string& alias,const Json& wanted){
    std::string image=wanted.at("image");std::wstring wide=Utf8(image).wstring();HMODULE h=nullptr;
    if(!GetModuleHandleExW(0,wide.c_str(),&h))throw std::runtime_error("WAITING_MODULE:"+alias);
    struct Ref {HMODULE handle;~Ref(){FreeLibrary(handle);}} ref{h};
    wchar_t path[32768];Require(GetModuleFileNameW(h,path,32768)>0,"module path");MODULEINFO info{};
    Require(GetModuleInformation(GetCurrentProcess(),h,&info,sizeof(info)),"module information");
    Module m;m.alias=alias;m.image=image;m.path=path;m.base=(uint64_t)h;m.size=info.SizeOfImage;m.sha=FileSha(m.path);
    Require(m.sha==wanted.at("sha256").get<std::string>(),"module hash mismatch");
    const auto [slot,epoch]=ObserveModule(m.base);m.epochSlot=slot;m.epoch=epoch;
    m.loadId=std::to_string(GetCurrentProcessId())+":"+std::to_string(m.base)+":"+std::to_string(epoch);return m;
}
Bytes ModuleFilePrefix(const Module& m,uint64_t rva,size_t length){
    std::ifstream file(m.path,std::ios::binary);Require(!!file,"module file unavailable");
    auto at=[&](uint64_t offset,void* out,size_t size){file.seekg((std::streamoff)offset);file.read((char*)out,size);Require(!!file,"PE header/file prefix truncated");};
    IMAGE_DOS_HEADER dos{};at(0,&dos,sizeof(dos));Require(dos.e_magic==IMAGE_DOS_SIGNATURE&&dos.e_lfanew>0,"PE DOS header");
    IMAGE_NT_HEADERS64 nt{};at(dos.e_lfanew,&nt,sizeof(nt));Require(nt.Signature==IMAGE_NT_SIGNATURE&&nt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC,"PE x64 header");
    uint64_t table=dos.e_lfanew+4+sizeof(IMAGE_FILE_HEADER)+nt.FileHeader.SizeOfOptionalHeader;
    for(unsigned i=0;i<nt.FileHeader.NumberOfSections;++i){IMAGE_SECTION_HEADER section{};at(table+i*sizeof(section),&section,sizeof(section));
        if(rva>=section.VirtualAddress&&rva-section.VirtualAddress<section.SizeOfRawData){
            auto delta=rva-section.VirtualAddress;Require(length<=section.SizeOfRawData-delta,"prefix extends beyond file section");
            Bytes bytes(length);at(section.PointerToRawData+delta,bytes.data(),length);return bytes;}}
    throw std::runtime_error("target RVA has no authoritative file bytes");
}
}
