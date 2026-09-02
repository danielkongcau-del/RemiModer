#include "d3d11_package.h"
#include <wrl/client.h>

namespace uc::d3d11 {
using Microsoft::WRL::ComPtr;

PackageWriter::PackageWriter(fs::path root) : root_(std::move(root)) {
    Require(!root_.empty(), "capture package root required");
    Require(!fs::exists(root_), "capture package already exists");
    Require(fs::create_directories(root_), "capture package root creation failed");
}

Json PackageWriter::AddArtifact(const std::string& id, const std::string& kind, const fs::path& relative,
                                const void* data, size_t size, const std::string& encoding) {
    Require(!id.empty() && !kind.empty() && !relative.empty(), "artifact identity required");
    Require(!relative.is_absolute(), "artifact path must be relative");
    for (const auto& part : relative) Require(part != L"..", "artifact path escapes package");
    const fs::path destination = root_ / relative;
    if (!destination.parent_path().empty()) Require(fs::create_directories(destination.parent_path()) ||
        fs::is_directory(destination.parent_path()), "artifact directory creation failed");
    NewFile(destination, data, size);
    const std::u8string encoded = relative.generic_u8string();
    std::string portable(reinterpret_cast<const char*>(encoded.data()), encoded.size());
    Json artifact = {{"id", id}, {"kind", kind}, {"path", portable}, {"sha256", Sha(data, size)},
                     {"size_bytes", size}, {"encoding", encoding}, {"lossless", true}};
    artifacts_.push_back(artifact);
    return artifact;
}

void PackageWriter::Seal(Json package) {
    Require(!package.contains("artifacts"), "manifest artifacts are writer-owned");
    package["artifacts"] = artifacts_;
    std::string text = package.dump(2);
    text.push_back('\n');
    NewFile(root_ / L"capture.json", text.data(), text.size());
}

Json DxgiFormat(DXGI_FORMAT value) {
    const char* name = nullptr;
    switch (value) {
    case DXGI_FORMAT_UNKNOWN: name = "DXGI_FORMAT_UNKNOWN"; break;
    case DXGI_FORMAT_R32G32B32_FLOAT: name = "DXGI_FORMAT_R32G32B32_FLOAT"; break;
    case DXGI_FORMAT_R32G32_FLOAT: name = "DXGI_FORMAT_R32G32_FLOAT"; break;
    case DXGI_FORMAT_R8G8B8A8_UNORM: name = "DXGI_FORMAT_R8G8B8A8_UNORM"; break;
    case DXGI_FORMAT_R16_UINT: name = "DXGI_FORMAT_R16_UINT"; break;
    case DXGI_FORMAT_R32_UINT: name = "DXGI_FORMAT_R32_UINT"; break;
    default: throw std::runtime_error("fixture uses an unmapped DXGI format");
    }
    return {{"value", static_cast<unsigned>(value)}, {"name", name}};
}

Json BufferDescriptor(const D3D11_BUFFER_DESC& value) {
    return Descriptor(value, {{"byte_width", value.ByteWidth}, {"usage", static_cast<unsigned>(value.Usage)},
        {"bind_flags", value.BindFlags}, {"cpu_access_flags", value.CPUAccessFlags}, {"misc_flags", value.MiscFlags},
        {"structure_byte_stride", value.StructureByteStride}});
}

Json Texture2DDescriptor(const D3D11_TEXTURE2D_DESC& value) {
    return Descriptor(value, {{"width", value.Width}, {"height", value.Height}, {"mip_levels", value.MipLevels},
        {"array_size", value.ArraySize}, {"format", DxgiFormat(value.Format)},
        {"sample_desc", {{"count", value.SampleDesc.Count}, {"quality", value.SampleDesc.Quality}}},
        {"usage", static_cast<unsigned>(value.Usage)}, {"bind_flags", value.BindFlags},
        {"cpu_access_flags", value.CPUAccessFlags}, {"misc_flags", value.MiscFlags}});
}

Json RenderTargetViewDescriptor(const D3D11_RENDER_TARGET_VIEW_DESC& value) {
    Json active;
    switch (value.ViewDimension) {
    case D3D11_RTV_DIMENSION_TEXTURE2D:
        active = {{"texture2d", {{"mip_slice", value.Texture2D.MipSlice}}}};
        break;
    default: throw std::runtime_error("fixture uses an unmapped RTV dimension");
    }
    return Descriptor(value, {{"format", DxgiFormat(value.Format)},
        {"view_dimension", static_cast<unsigned>(value.ViewDimension)}, {"union", std::move(active)}});
}

Json RasterizerDescriptor(const D3D11_RASTERIZER_DESC& value) {
    return Descriptor(value, {{"fill_mode", static_cast<unsigned>(value.FillMode)},
        {"cull_mode", static_cast<unsigned>(value.CullMode)}, {"front_counter_clockwise", !!value.FrontCounterClockwise},
        {"depth_bias", value.DepthBias}, {"depth_bias_clamp", value.DepthBiasClamp},
        {"slope_scaled_depth_bias", value.SlopeScaledDepthBias}, {"depth_clip_enable", !!value.DepthClipEnable},
        {"scissor_enable", !!value.ScissorEnable}, {"multisample_enable", !!value.MultisampleEnable},
        {"antialiased_line_enable", !!value.AntialiasedLineEnable}});
}

std::string FeatureLevel(D3D_FEATURE_LEVEL value) {
    switch (value) {
    case D3D_FEATURE_LEVEL_11_0: return "D3D_FEATURE_LEVEL_11_0";
    case D3D_FEATURE_LEVEL_11_1: return "D3D_FEATURE_LEVEL_11_1";
    case D3D_FEATURE_LEVEL_10_0: return "D3D_FEATURE_LEVEL_10_0";
    case D3D_FEATURE_LEVEL_10_1: return "D3D_FEATURE_LEVEL_10_1";
    default: throw std::runtime_error("unsupported fixture feature level");
    }
}

std::string AdapterLuid(LUID value) {
    char text[17]{};
    sprintf_s(text, "%08x%08x", static_cast<unsigned>(value.HighPart), value.LowPart);
    return text;
}

Json ReflectRequirements(const void* dxbc, size_t size) {
    ComPtr<ID3D11ShaderReflection> reflection;
    Require(SUCCEEDED(D3DReflect(dxbc, size, IID_PPV_ARGS(&reflection))), "DXBC reflection failed");
    D3D11_SHADER_DESC shader{};
    Require(SUCCEEDED(reflection->GetDesc(&shader)), "DXBC reflection descriptor failed");
    Json result = {{"constant_buffers", Json::array()}, {"srvs", Json::array()},
                   {"samplers", Json::array()}, {"uavs", Json::array()}};
    for (unsigned index = 0; index < shader.BoundResources; ++index) {
        D3D11_SHADER_INPUT_BIND_DESC binding{};
        Require(SUCCEEDED(reflection->GetResourceBindingDesc(index, &binding)), "DXBC binding reflection failed");
        const char* group = nullptr;
        switch (binding.Type) {
        case D3D_SIT_CBUFFER: group = "constant_buffers"; break;
        case D3D_SIT_SAMPLER: group = "samplers"; break;
        case D3D_SIT_TEXTURE: case D3D_SIT_TBUFFER: case D3D_SIT_STRUCTURED: case D3D_SIT_BYTEADDRESS:
            group = "srvs"; break;
        case D3D_SIT_UAV_RWTYPED: case D3D_SIT_UAV_RWSTRUCTURED: case D3D_SIT_UAV_RWBYTEADDRESS:
        case D3D_SIT_UAV_APPEND_STRUCTURED: case D3D_SIT_UAV_CONSUME_STRUCTURED:
        case D3D_SIT_UAV_RWSTRUCTURED_WITH_COUNTER: group = "uavs"; break;
        default: throw std::runtime_error("unmapped DXBC binding type");
        }
        for (unsigned slot = 0; slot < binding.BindCount; ++slot) result[group].push_back(binding.BindPoint + slot);
    }
    for (auto& [_, slots] : result.items()) {
        std::sort(slots.begin(), slots.end());
        slots.erase(std::unique(slots.begin(), slots.end()), slots.end());
    }
    return result;
}

}
