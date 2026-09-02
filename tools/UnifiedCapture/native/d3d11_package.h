#pragma once

#include "common.h"
#include <d3d11.h>
#include <d3d11shader.h>
#include <d3dcompiler.h>
#include <algorithm>
#include <type_traits>

namespace uc::d3d11 {

class PackageWriter {
    fs::path root_;
    Json artifacts_ = Json::array();
public:
    explicit PackageWriter(fs::path root);
    Json AddArtifact(const std::string& id, const std::string& kind, const fs::path& relative,
                     const void* data, size_t size, const std::string& encoding = "raw");
    void Seal(Json package);
    const fs::path& Root() const noexcept { return root_; }
};

template <typename T>
Json Descriptor(const T& value, Json decoded) {
    static_assert(std::is_trivially_copyable_v<T>);
    return {{"raw_hex", Hex(&value, sizeof(value))}, {"decoded", std::move(decoded)}};
}

Json BufferDescriptor(const D3D11_BUFFER_DESC& value);
Json Texture2DDescriptor(const D3D11_TEXTURE2D_DESC& value);
Json RenderTargetViewDescriptor(const D3D11_RENDER_TARGET_VIEW_DESC& value);
Json RasterizerDescriptor(const D3D11_RASTERIZER_DESC& value);
Json DxgiFormat(DXGI_FORMAT value);
std::string FeatureLevel(D3D_FEATURE_LEVEL value);
std::string AdapterLuid(LUID value);
Json ReflectRequirements(const void* dxbc, size_t size);

}
