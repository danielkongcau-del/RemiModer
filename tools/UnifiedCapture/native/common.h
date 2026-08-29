#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <compressapi.h>
#include <psapi.h>
#include <atomic>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include "json.hpp"

namespace uc {
using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
namespace fs = std::filesystem;
inline fs::path Utf8(const std::string& text) {
    return fs::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()),text.size()));
}
inline uint64_t Clock() { LARGE_INTEGER q; QueryPerformanceCounter(&q); return q.QuadPart; }
inline uint64_t Frequency() { LARGE_INTEGER q; QueryPerformanceFrequency(&q); return q.QuadPart; }
std::string Hex(const void*, size_t);
Bytes Unhex(const std::string&);
std::string Sha(const void*, size_t);
std::string FileSha(const fs::path&);
uint32_t Crc(const void*, size_t);
bool Read(uint64_t, void*, size_t) noexcept;
Bytes ReadFile(const fs::path&);
void NewFile(const fs::path&, const void*, size_t);
void AppendFile(const fs::path&, const void*, size_t);
std::string UniqueId();
std::string WallClockUtc();
inline void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
inline uint64_t U64(const Json& value) {
    Require(value.is_number_integer() && !value.is_boolean(), "expected unsigned integer");
    if (value.is_number_integer() && !value.is_number_unsigned()) Require(value.get<int64_t>() >= 0, "negative integer");
    return value.get<uint64_t>();
}
inline uint64_t Add(uint64_t base, uint64_t delta) {
    Require(base <= UINT64_MAX-delta, "address/size overflow"); return base+delta;
}
inline Bytes JsonBytes(const Json& j) { auto s=j.dump(); return Bytes(s.begin(),s.end()); }

struct Module {
    std::string alias, image, sha, loadId;
    uint64_t base=0, size=0;
    uint32_t epochSlot=UINT32_MAX;uint64_t epoch=0;
    fs::path path;
};
Module ResolveModule(const std::string&, const Json&);
Bytes ModuleFilePrefix(const Module&,uint64_t,size_t);
}
