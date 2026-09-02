#include "d3d11_observer.h"
#include "d3d11_package.h"
#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>
#include <deque>
#include <unordered_map>
#include <unordered_set>

namespace uc::d3d11 {
using Microsoft::WRL::ComPtr;

namespace {
enum class Kind {
    CreateDevice,
    CreateDeviceAndSwapChain,
    CreateBuffer,
    CreateTexture1D,
    CreateTexture2D,
    CreateTexture3D,
    CreateSrv,
    CreateUav,
    CreateRtv,
    CreateDsv,
    CreateInputLayout,
    CreateVs,
    CreateGs,
    CreateGsWithSo,
    CreatePs,
    CreateHs,
    CreateDs,
    CreateCs,
    CreateBlend,
    CreateDepthStencil,
    CreateRasterizer,
    CreateSampler,
    Draw,
    DrawIndexed,
    DrawInstanced,
    DrawIndexedInstanced,
    DrawAuto,
    DrawInstancedIndirect,
    DrawIndexedInstancedIndirect,
    Present,
};

struct Invocation {
    std::array<void*, 12> arguments{};
    void* captureJob = nullptr;
};

const char* KindName(Kind kind) noexcept {
    switch (kind) {
    case Kind::CreateDevice: return "D3D11CreateDevice";
    case Kind::CreateDeviceAndSwapChain: return "D3D11CreateDeviceAndSwapChain";
    case Kind::CreateBuffer: return "CreateBuffer";
    case Kind::CreateTexture1D: return "CreateTexture1D";
    case Kind::CreateTexture2D: return "CreateTexture2D";
    case Kind::CreateTexture3D: return "CreateTexture3D";
    case Kind::CreateSrv: return "CreateShaderResourceView";
    case Kind::CreateUav: return "CreateUnorderedAccessView";
    case Kind::CreateRtv: return "CreateRenderTargetView";
    case Kind::CreateDsv: return "CreateDepthStencilView";
    case Kind::CreateInputLayout: return "CreateInputLayout";
    case Kind::CreateVs: return "CreateVertexShader";
    case Kind::CreateGs: return "CreateGeometryShader";
    case Kind::CreateGsWithSo: return "CreateGeometryShaderWithStreamOutput";
    case Kind::CreatePs: return "CreatePixelShader";
    case Kind::CreateHs: return "CreateHullShader";
    case Kind::CreateDs: return "CreateDomainShader";
    case Kind::CreateCs: return "CreateComputeShader";
    case Kind::CreateBlend: return "CreateBlendState";
    case Kind::CreateDepthStencil: return "CreateDepthStencilState";
    case Kind::CreateRasterizer: return "CreateRasterizerState";
    case Kind::CreateSampler: return "CreateSamplerState";
    case Kind::Draw: return "Draw";
    case Kind::DrawIndexed: return "DrawIndexed";
    case Kind::DrawInstanced: return "DrawInstanced";
    case Kind::DrawIndexedInstanced: return "DrawIndexedInstanced";
    case Kind::DrawAuto: return "DrawAuto";
    case Kind::DrawInstancedIndirect: return "DrawInstancedIndirect";
    case Kind::DrawIndexedInstancedIndirect: return "DrawIndexedInstancedIndirect";
    case Kind::Present: return "Present";
    }
    return "unknown";
}

bool IsShader(Kind kind) noexcept {
    return kind == Kind::CreateVs || kind == Kind::CreateGs || kind == Kind::CreateGsWithSo ||
        kind == Kind::CreatePs || kind == Kind::CreateHs || kind == Kind::CreateDs || kind == Kind::CreateCs;
}

bool IsDraw(Kind kind) noexcept {
    return kind == Kind::Draw || kind == Kind::DrawIndexed || kind == Kind::DrawInstanced ||
        kind == Kind::DrawIndexedInstanced || kind == Kind::DrawAuto ||
        kind == Kind::DrawInstancedIndirect || kind == Kind::DrawIndexedInstancedIndirect;
}

const char* ShaderStage(Kind kind) noexcept {
    switch (kind) {
    case Kind::CreateVs: return "vs";
    case Kind::CreateGs: case Kind::CreateGsWithSo: return "gs";
    case Kind::CreatePs: return "ps";
    case Kind::CreateHs: return "hs";
    case Kind::CreateDs: return "ds";
    case Kind::CreateCs: return "cs";
    default: return "";
    }
}

template<class T> T* Output(void* address) noexcept {
    if (!address) return nullptr;
    T* result = nullptr;
    return Read(reinterpret_cast<uint64_t>(address), &result, sizeof(result)) ? result : nullptr;
}

Json Pointer(void* value) {
    char text[19]{};
    sprintf_s(text, "0x%016llx", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(value)));
    return text;
}
}

struct Observer::Impl {
    struct HookSpec {
        Impl* owner = nullptr;
        Kind kind{};
        void* target = nullptr;
        GumInvocationListener* listener = nullptr;
    };
    struct ShaderRecord {
        std::string stage;
        std::string sha256;
        Bytes bytecode;
    };
    struct LayoutElement {
        std::string semantic;
        UINT semanticIndex = 0;
        DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
        UINT inputSlot = 0;
        UINT alignedByteOffset = 0;
        D3D11_INPUT_CLASSIFICATION slotClass = D3D11_INPUT_PER_VERTEX_DATA;
        UINT instanceStepRate = 0;
    };
    struct LayoutRecord {
        std::string signatureSha256;
        Bytes signature;
        std::vector<LayoutElement> elements;
    };
    struct PendingOutput {
        fs::path relative;
        Bytes bytes;
    };
    struct CaptureJob {
        Json catalog;
        std::vector<PendingOutput> outputs;
        std::vector<ComPtr<ID3D11Resource>> outputResources;
        ComPtr<ID3D11DeviceContext> context;
        std::string suffix;
    };

    GumInterceptor* interceptor = nullptr;
    fs::path observerDirectory;
    fs::path outputRoot;
    Json configuration;
    mutable std::mutex mutex;
    std::deque<HookSpec> hooks;
    std::unordered_set<void*> targets;
    std::unordered_map<void*, ShaderRecord> shaders;
    std::unordered_map<void*, LayoutRecord> layouts;
    std::unordered_set<void*> devices;
    std::unordered_set<void*> contexts;
    std::unordered_set<void*> swapchains;
    std::deque<Json> pendingFiles;
    std::deque<PendingOutput> pendingOutputs;
    std::atomic<bool> exportHooksReady{false};
    std::atomic<bool> armed{false};
    std::atomic<bool> captured{false};
    std::atomic<uint64_t> capturesReserved{0};
    std::atomic<uint64_t> frames{0};
    std::atomic<uint64_t> drawsObserved{0};
    std::atomic<uint64_t> matchingDraws{0};
    std::atomic<uint64_t> shadersObserved{0};
    std::atomic<uint64_t> layoutsObserved{0};
    std::string armLabel;
    std::string requiredPsSha256;
    std::string requiredVsSha256;
    std::atomic<uint64_t> armCounter{0};
    bool armAtStart = false;
    bool catalogOnly = false;
    uint64_t maxCaptures = 1;
    std::string error;

    Impl(GumInterceptor* gum, fs::path directory, Json config)
        : interceptor(gum), observerDirectory(std::move(directory)), configuration(std::move(config)) {
        Require(interceptor != nullptr, "D3D11 observer requires Gum interceptor");
        wchar_t environmentRoot[32768]{};
        const DWORD environmentSize = GetEnvironmentVariableW(L"UC_D3D11_CAPTURE_ROOT", environmentRoot,
            static_cast<DWORD>(std::size(environmentRoot)));
        Require(environmentSize < std::size(environmentRoot), "UC_D3D11_CAPTURE_ROOT is too long");
        outputRoot = environmentSize ? fs::path(environmentRoot) : configuration.contains("output_root")
            ? fs::path(Utf8(configuration.at("output_root").get<std::string>()))
            : observerDirectory / L"d3d11-captures";
        requiredPsSha256 = configuration.value("pixel_shader_sha256", "");
        requiredVsSha256 = configuration.value("vertex_shader_sha256", "");
        std::transform(requiredPsSha256.begin(), requiredPsSha256.end(), requiredPsSha256.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(requiredVsSha256.begin(), requiredVsSha256.end(), requiredVsSha256.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        catalogOnly = configuration.value("catalog_only", false);
        maxCaptures = configuration.value("max_captures", 1ULL);
        Require(maxCaptures > 0 && maxCaptures <= 256, "D3D11 max_captures must be within 1..256");
        armAtStart = configuration.value("arm_at_start", false);
        armed.store(armAtStart, std::memory_order_release);
        if (armAtStart) armLabel = "bootstrap";
    }

    ~Impl() {
        for (auto& hook : hooks) {
            if (!hook.listener) continue;
            gum_interceptor_detach(interceptor, hook.listener);
            gum_interceptor_flush_listener(interceptor, hook.listener);
            g_object_unref(hook.listener);
        }
    }

    static void OnEnter(GumInvocationContext* context, gpointer data) noexcept {
        auto& hook = *static_cast<HookSpec*>(data);
        try { hook.owner->Enter(hook.kind, context); }
        catch (const std::exception& exception) { hook.owner->SetError(exception.what()); }
        catch (...) { hook.owner->SetError("unknown D3D11 enter callback failure"); }
    }

    static void OnLeave(GumInvocationContext* context, gpointer data) noexcept {
        auto& hook = *static_cast<HookSpec*>(data);
        try { hook.owner->Leave(hook.kind, context); }
        catch (const std::exception& exception) { hook.owner->SetError(exception.what()); }
        catch (...) { hook.owner->SetError("unknown D3D11 leave callback failure"); }
    }

    void SetError(std::string value) noexcept {
        std::lock_guard lock(mutex);
        if (error.empty()) error = std::move(value);
    }

    bool Attach(void* target, Kind kind) {
        if (!target || targets.contains(target)) return false;
        hooks.push_back({this, kind, target, nullptr});
        HookSpec& hook = hooks.back();
        hook.listener = gum_make_call_listener(OnEnter, OnLeave, &hook, nullptr);
        Require(hook.listener != nullptr, "D3D11 Gum listener allocation failed");
        GumAttachOptions options{};
        const GumAttachReturn result = gum_interceptor_attach(interceptor, target, hook.listener, &options);
        if (result != GUM_ATTACH_OK) {
            g_object_unref(hook.listener);
            hook.listener = nullptr;
            hooks.pop_back();
            if (result == GUM_ATTACH_ALREADY_ATTACHED) return false;
            throw std::runtime_error("D3D11 Gum attach failed for " + std::string(KindName(kind)) +
                ": " + std::to_string(static_cast<int>(result)));
        }
        targets.insert(target);
        return true;
    }

    void AttachExports() {
        HMODULE module = GetModuleHandleW(L"d3d11.dll");
        if (!module) return;
        gum_interceptor_begin_transaction(interceptor);
        try {
            Attach(reinterpret_cast<void*>(GetProcAddress(module, "D3D11CreateDevice")), Kind::CreateDevice);
            Attach(reinterpret_cast<void*>(GetProcAddress(module, "D3D11CreateDeviceAndSwapChain")), Kind::CreateDeviceAndSwapChain);
            gum_interceptor_end_transaction(interceptor);
            exportHooksReady.store(true, std::memory_order_release);
        } catch (...) {
            gum_interceptor_end_transaction(interceptor);
            throw;
        }
    }

    void AttachDevice(ID3D11Device* device, ID3D11DeviceContext* context) {
        if (!device || !context) return;
        std::lock_guard lock(mutex);
        if (devices.contains(device) && contexts.contains(context)) return;
        void** deviceVtable = *reinterpret_cast<void***>(device);
        void** contextVtable = *reinterpret_cast<void***>(context);
        static constexpr std::pair<unsigned, Kind> deviceMethods[] = {
            {3, Kind::CreateBuffer}, {4, Kind::CreateTexture1D}, {5, Kind::CreateTexture2D},
            {6, Kind::CreateTexture3D}, {7, Kind::CreateSrv}, {8, Kind::CreateUav}, {9, Kind::CreateRtv},
            {10, Kind::CreateDsv}, {11, Kind::CreateInputLayout}, {12, Kind::CreateVs}, {13, Kind::CreateGs},
            {14, Kind::CreateGsWithSo}, {15, Kind::CreatePs}, {16, Kind::CreateHs}, {17, Kind::CreateDs},
            {18, Kind::CreateCs}, {20, Kind::CreateBlend}, {21, Kind::CreateDepthStencil},
            {22, Kind::CreateRasterizer}, {23, Kind::CreateSampler},
        };
        static constexpr std::pair<unsigned, Kind> contextMethods[] = {
            {12, Kind::DrawIndexed}, {13, Kind::Draw}, {20, Kind::DrawIndexedInstanced},
            {21, Kind::DrawInstanced}, {38, Kind::DrawAuto}, {39, Kind::DrawIndexedInstancedIndirect},
            {40, Kind::DrawInstancedIndirect},
        };
        gum_interceptor_begin_transaction(interceptor);
        try {
            for (const auto [index, kind] : deviceMethods) Attach(deviceVtable[index], kind);
            for (const auto [index, kind] : contextMethods) Attach(contextVtable[index], kind);
            gum_interceptor_end_transaction(interceptor);
        } catch (...) {
            gum_interceptor_end_transaction(interceptor);
            throw;
        }
        devices.insert(device);
        contexts.insert(context);
    }

    void AttachSwapchain(IDXGISwapChain* swapchain) {
        if (!swapchain) return;
        std::lock_guard lock(mutex);
        if (swapchains.contains(swapchain)) return;
        void** vtable = *reinterpret_cast<void***>(swapchain);
        Attach(vtable[8], Kind::Present);
        swapchains.insert(swapchain);
    }

    void Enter(Kind kind, GumInvocationContext* context) {
        auto* invocation = static_cast<Invocation*>(
            gum_invocation_context_get_listener_invocation_data(context, sizeof(Invocation)));
        if (!invocation) return;
        invocation->captureJob = nullptr;
        for (unsigned index = 0; index < invocation->arguments.size(); ++index)
            invocation->arguments[index] = gum_invocation_context_get_nth_argument(context, index);
        if (IsDraw(kind)) invocation->captureJob = ObserveDraw(kind, invocation->arguments);
    }

    void Leave(Kind kind, GumInvocationContext* context) {
        auto* invocation = static_cast<Invocation*>(
            gum_invocation_context_get_listener_invocation_data(context, sizeof(Invocation)));
        if (!invocation) return;
        const auto result = static_cast<HRESULT>(reinterpret_cast<intptr_t>(
            gum_invocation_context_get_return_value(context)));
        if ((kind == Kind::CreateDevice || kind == Kind::CreateDeviceAndSwapChain) && SUCCEEDED(result)) {
            if (kind == Kind::CreateDevice) {
                AttachDevice(Output<ID3D11Device>(invocation->arguments[7]),
                    Output<ID3D11DeviceContext>(invocation->arguments[9]));
            } else {
                AttachSwapchain(Output<IDXGISwapChain>(invocation->arguments[8]));
                AttachDevice(Output<ID3D11Device>(invocation->arguments[9]),
                    Output<ID3D11DeviceContext>(invocation->arguments[11]));
            }
            return;
        }
        if (IsDraw(kind)) {
            if (invocation->captureJob) CompleteDraw(std::unique_ptr<CaptureJob>(
                static_cast<CaptureJob*>(invocation->captureJob)));
            return;
        }
        if (kind == Kind::Present) {
            frames.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (FAILED(result)) return;
        if (IsShader(kind)) RecordShader(kind, invocation->arguments);
        else if (kind == Kind::CreateInputLayout) RecordLayout(invocation->arguments);
    }

    void RecordShader(Kind kind, const std::array<void*, 12>& arguments) {
        const unsigned outputIndex = kind == Kind::CreateGsWithSo ? 9U : 4U;
        void* object = Output<void>(arguments[outputIndex]);
        const void* bytes = arguments[1];
        const size_t size = reinterpret_cast<size_t>(arguments[2]);
        if (!object || !bytes || !size) return;
        ShaderRecord record;
        record.stage = ShaderStage(kind);
        record.bytecode.resize(size);
        Require(Read(reinterpret_cast<uint64_t>(bytes), record.bytecode.data(), size),
            "shader bytecode became unreadable before Create*Shader returned");
        record.sha256 = Sha(record.bytecode.data(), record.bytecode.size());
        std::lock_guard lock(mutex);
        shaders.insert_or_assign(object, std::move(record));
        shadersObserved.fetch_add(1, std::memory_order_relaxed);
    }

    void RecordLayout(const std::array<void*, 12>& arguments) {
        void* object = Output<void>(arguments[5]);
        auto* source = static_cast<const D3D11_INPUT_ELEMENT_DESC*>(arguments[1]);
        const UINT count = static_cast<UINT>(reinterpret_cast<uintptr_t>(arguments[2]));
        const void* signature = arguments[3];
        const size_t signatureSize = reinterpret_cast<size_t>(arguments[4]);
        if (!object || (!source && count) || !signature || !signatureSize) return;
        std::vector<D3D11_INPUT_ELEMENT_DESC> elements(count);
        if (count) Require(Read(reinterpret_cast<uint64_t>(source), elements.data(), sizeof(elements[0]) * count),
            "input layout elements became unreadable before CreateInputLayout returned");
        Bytes signatureBytes(signatureSize);
        Require(Read(reinterpret_cast<uint64_t>(signature), signatureBytes.data(), signatureSize),
            "input layout signature became unreadable before CreateInputLayout returned");
        LayoutRecord record;
        record.signatureSha256 = Sha(signatureBytes.data(), signatureBytes.size());
        record.signature = std::move(signatureBytes);
        for (const auto& element : elements) {
            LayoutElement copied;
            copied.semantic = element.SemanticName ? element.SemanticName : "";
            copied.semanticIndex = element.SemanticIndex;
            copied.format = element.Format;
            copied.inputSlot = element.InputSlot;
            copied.alignedByteOffset = element.AlignedByteOffset;
            copied.slotClass = element.InputSlotClass;
            copied.instanceStepRate = element.InstanceDataStepRate;
            record.elements.push_back(std::move(copied));
        }
        std::lock_guard lock(mutex);
        layouts.insert_or_assign(object, std::move(record));
        layoutsObserved.fetch_add(1, std::memory_order_relaxed);
    }

    Json DrawArguments(Kind kind, const std::array<void*, 12>& arguments) const {
        auto u32 = [&](unsigned index) { return static_cast<UINT>(reinterpret_cast<uintptr_t>(arguments[index])); };
        switch (kind) {
        case Kind::Draw: return {{"vertex_count", u32(1)}, {"start_vertex", u32(2)}};
        case Kind::DrawIndexed: return {{"index_count", u32(1)}, {"start_index", u32(2)},
            {"base_vertex", static_cast<INT>(u32(3))}};
        case Kind::DrawInstanced: return {{"vertices_per_instance", u32(1)}, {"instance_count", u32(2)},
            {"start_vertex", u32(3)}, {"start_instance", u32(4)}};
        case Kind::DrawIndexedInstanced: return {{"indices_per_instance", u32(1)}, {"instance_count", u32(2)},
            {"start_index", u32(3)}, {"base_vertex", static_cast<INT>(u32(4))}, {"start_instance", u32(5)}};
        case Kind::DrawAuto: return Json::object();
        case Kind::DrawInstancedIndirect: case Kind::DrawIndexedInstancedIndirect:
            return {{"argument_buffer", Pointer(arguments[1])}, {"aligned_byte_offset", u32(2)}};
        default: return Json::object();
        }
    }

    template<class T>
    Json RawDescriptor(const T& descriptor, Json decoded = Json::object()) const {
        return {{"raw_hex", Hex(&descriptor, sizeof(descriptor))}, {"decoded", std::move(decoded)}};
    }

    Json BufferObject(ID3D11Buffer* buffer) const {
        if (!buffer) return nullptr;
        D3D11_BUFFER_DESC descriptor{};
        buffer->GetDesc(&descriptor);
        return {{"object", Pointer(buffer)}, {"descriptor", BufferDescriptor(descriptor)}};
    }

    Json ResourceObject(ID3D11Resource* resource) const {
        if (!resource) return nullptr;
        D3D11_RESOURCE_DIMENSION dimension = D3D11_RESOURCE_DIMENSION_UNKNOWN;
        resource->GetType(&dimension);
        Json result = {{"object", Pointer(resource)}, {"dimension", static_cast<unsigned>(dimension)}};
        if (dimension == D3D11_RESOURCE_DIMENSION_BUFFER) {
            ComPtr<ID3D11Buffer> value;
            if (SUCCEEDED(resource->QueryInterface(IID_PPV_ARGS(&value)))) result["descriptor"] = BufferObject(value.Get())["descriptor"];
        } else if (dimension == D3D11_RESOURCE_DIMENSION_TEXTURE1D) {
            ComPtr<ID3D11Texture1D> value; D3D11_TEXTURE1D_DESC descriptor{};
            if (SUCCEEDED(resource->QueryInterface(IID_PPV_ARGS(&value)))) {
                value->GetDesc(&descriptor);
                result["descriptor"] = RawDescriptor(descriptor, {{"width", descriptor.Width},
                    {"mip_levels", descriptor.MipLevels}, {"array_size", descriptor.ArraySize},
                    {"format", static_cast<unsigned>(descriptor.Format)}, {"usage", static_cast<unsigned>(descriptor.Usage)},
                    {"bind_flags", descriptor.BindFlags}, {"cpu_access_flags", descriptor.CPUAccessFlags},
                    {"misc_flags", descriptor.MiscFlags}});
            }
        } else if (dimension == D3D11_RESOURCE_DIMENSION_TEXTURE2D) {
            ComPtr<ID3D11Texture2D> value; D3D11_TEXTURE2D_DESC descriptor{};
            if (SUCCEEDED(resource->QueryInterface(IID_PPV_ARGS(&value)))) {
                value->GetDesc(&descriptor);
                result["descriptor"] = RawDescriptor(descriptor, {{"width", descriptor.Width}, {"height", descriptor.Height},
                    {"mip_levels", descriptor.MipLevels}, {"array_size", descriptor.ArraySize},
                    {"format", static_cast<unsigned>(descriptor.Format)},
                    {"sample_count", descriptor.SampleDesc.Count}, {"sample_quality", descriptor.SampleDesc.Quality},
                    {"usage", static_cast<unsigned>(descriptor.Usage)}, {"bind_flags", descriptor.BindFlags},
                    {"cpu_access_flags", descriptor.CPUAccessFlags}, {"misc_flags", descriptor.MiscFlags}});
            }
        } else if (dimension == D3D11_RESOURCE_DIMENSION_TEXTURE3D) {
            ComPtr<ID3D11Texture3D> value; D3D11_TEXTURE3D_DESC descriptor{};
            if (SUCCEEDED(resource->QueryInterface(IID_PPV_ARGS(&value)))) {
                value->GetDesc(&descriptor);
                result["descriptor"] = RawDescriptor(descriptor, {{"width", descriptor.Width}, {"height", descriptor.Height},
                    {"depth", descriptor.Depth}, {"mip_levels", descriptor.MipLevels},
                    {"format", static_cast<unsigned>(descriptor.Format)}, {"usage", static_cast<unsigned>(descriptor.Usage)},
                    {"bind_flags", descriptor.BindFlags}, {"cpu_access_flags", descriptor.CPUAccessFlags},
                    {"misc_flags", descriptor.MiscFlags}});
            }
        }
        return result;
    }

    Json SrvObject(ID3D11ShaderResourceView* view) const {
        if (!view) return nullptr;
        D3D11_SHADER_RESOURCE_VIEW_DESC descriptor{};
        view->GetDesc(&descriptor);
        ComPtr<ID3D11Resource> resource;
        view->GetResource(&resource);
        return {{"object", Pointer(view)}, {"descriptor", RawDescriptor(descriptor,
            {{"format", static_cast<unsigned>(descriptor.Format)}, {"view_dimension", static_cast<unsigned>(descriptor.ViewDimension)}})},
            {"resource", ResourceObject(resource.Get())}};
    }

    Json SamplerObject(ID3D11SamplerState* sampler) const {
        if (!sampler) return nullptr;
        D3D11_SAMPLER_DESC descriptor{};
        sampler->GetDesc(&descriptor);
        return {{"object", Pointer(sampler)}, {"descriptor", RawDescriptor(descriptor,
            {{"filter", static_cast<unsigned>(descriptor.Filter)}, {"address_u", static_cast<unsigned>(descriptor.AddressU)},
             {"address_v", static_cast<unsigned>(descriptor.AddressV)}, {"address_w", static_cast<unsigned>(descriptor.AddressW)},
             {"mip_lod_bias", descriptor.MipLODBias}, {"max_anisotropy", descriptor.MaxAnisotropy},
             {"comparison_func", static_cast<unsigned>(descriptor.ComparisonFunc)},
             {"border_color", Json::array({descriptor.BorderColor[0], descriptor.BorderColor[1],
                 descriptor.BorderColor[2], descriptor.BorderColor[3]})},
             {"min_lod", descriptor.MinLOD}, {"max_lod", descriptor.MaxLOD}})}};
    }

    Json ShaderObject(void* shader, const char* stage) const {
        if (!shader) return nullptr;
        std::lock_guard lock(mutex);
        auto found = shaders.find(shader);
        if (found == shaders.end()) return {{"object", Pointer(shader)}, {"stage", stage}, {"startup_bytecode", false}};
        return {{"object", Pointer(shader)}, {"stage", stage}, {"startup_bytecode", true},
            {"sha256", found->second.sha256}, {"bytecode_size", found->second.bytecode.size()}};
    }

    template<class Shader, class GetShader, class GetBuffers, class GetSrvs, class GetSamplers>
    Json GraphicsStage(const char* name, GetShader getShader, GetBuffers getBuffers, GetSrvs getSrvs,
                       GetSamplers getSamplers) const {
        Shader* rawShader = nullptr;
        std::array<ID3D11ClassInstance*, 256> rawClasses{};
        UINT classCount = static_cast<UINT>(rawClasses.size());
        getShader(&rawShader, rawClasses.data(), &classCount);
        ComPtr<Shader> shader; shader.Attach(rawShader);
        Json classes = Json::array();
        for (UINT index = 0; index < std::min(classCount, static_cast<UINT>(rawClasses.size())); ++index) {
            if (rawClasses[index]) { classes.push_back(Pointer(rawClasses[index])); rawClasses[index]->Release(); }
        }
        std::array<ID3D11Buffer*, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT> rawBuffers{};
        getBuffers(0, static_cast<UINT>(rawBuffers.size()), rawBuffers.data());
        Json buffers = Json::array();
        for (UINT slot = 0; slot < rawBuffers.size(); ++slot) if (rawBuffers[slot]) {
            buffers.push_back({{"slot", slot}, {"value", BufferObject(rawBuffers[slot])}}); rawBuffers[slot]->Release();
        }
        std::array<ID3D11ShaderResourceView*, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT> rawSrvs{};
        getSrvs(0, static_cast<UINT>(rawSrvs.size()), rawSrvs.data());
        Json srvs = Json::array();
        for (UINT slot = 0; slot < rawSrvs.size(); ++slot) if (rawSrvs[slot]) {
            srvs.push_back({{"slot", slot}, {"value", SrvObject(rawSrvs[slot])}}); rawSrvs[slot]->Release();
        }
        std::array<ID3D11SamplerState*, D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT> rawSamplers{};
        getSamplers(0, static_cast<UINT>(rawSamplers.size()), rawSamplers.data());
        Json samplers = Json::array();
        for (UINT slot = 0; slot < rawSamplers.size(); ++slot) if (rawSamplers[slot]) {
            samplers.push_back({{"slot", slot}, {"value", SamplerObject(rawSamplers[slot])}}); rawSamplers[slot]->Release();
        }
        return {{"shader", ShaderObject(shader.Get(), name)}, {"class_instances", std::move(classes)},
            {"constant_buffers", std::move(buffers)}, {"srvs", std::move(srvs)}, {"samplers", std::move(samplers)}};
    }

    Json PipelineIdentity(ID3D11DeviceContext* context) const {
        Json pipeline;
        ID3D11InputLayout* rawLayout = nullptr;
        context->IAGetInputLayout(&rawLayout);
        ComPtr<ID3D11InputLayout> layout; layout.Attach(rawLayout);
        Json layoutValue = nullptr;
        if (layout) {
            std::lock_guard lock(mutex);
            auto found = layouts.find(layout.Get());
            if (found == layouts.end()) layoutValue = {{"object", Pointer(layout.Get())}, {"startup_descriptor", false}};
            else {
                Json elements = Json::array();
                for (const auto& element : found->second.elements) elements.push_back({
                    {"semantic_name", element.semantic}, {"semantic_index", element.semanticIndex},
                    {"format", static_cast<unsigned>(element.format)}, {"input_slot", element.inputSlot},
                    {"aligned_byte_offset", element.alignedByteOffset},
                    {"input_slot_class", static_cast<unsigned>(element.slotClass)},
                    {"instance_data_step_rate", element.instanceStepRate}});
                layoutValue = {{"object", Pointer(layout.Get())}, {"startup_descriptor", true},
                    {"signature_sha256", found->second.signatureSha256}, {"elements", std::move(elements)}};
            }
        }
        std::array<ID3D11Buffer*, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT> rawVertexBuffers{};
        std::array<UINT, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT> strides{}, offsets{};
        context->IAGetVertexBuffers(0, static_cast<UINT>(rawVertexBuffers.size()), rawVertexBuffers.data(), strides.data(), offsets.data());
        Json vertexBuffers = Json::array();
        for (UINT slot = 0; slot < rawVertexBuffers.size(); ++slot) if (rawVertexBuffers[slot]) {
            vertexBuffers.push_back({{"slot", slot}, {"stride", strides[slot]}, {"offset", offsets[slot]},
                {"value", BufferObject(rawVertexBuffers[slot])}}); rawVertexBuffers[slot]->Release();
        }
        ID3D11Buffer* rawIndex = nullptr; DXGI_FORMAT indexFormat = DXGI_FORMAT_UNKNOWN; UINT indexOffset = 0;
        context->IAGetIndexBuffer(&rawIndex, &indexFormat, &indexOffset);
        ComPtr<ID3D11Buffer> index; index.Attach(rawIndex);
        D3D11_PRIMITIVE_TOPOLOGY topology{}; context->IAGetPrimitiveTopology(&topology);
        pipeline["input_assembler"] = {{"input_layout", std::move(layoutValue)},
            {"vertex_buffers", std::move(vertexBuffers)},
            {"index_buffer", index ? Json{{"format", static_cast<unsigned>(indexFormat)}, {"offset", indexOffset},
                {"value", BufferObject(index.Get())}} : Json(nullptr)}, {"primitive_topology", static_cast<unsigned>(topology)}};

        pipeline["stages"] = {
            {"vs", GraphicsStage<ID3D11VertexShader>("vs",
                [&](auto a, auto b, auto c) { context->VSGetShader(a, b, c); },
                [&](auto a, auto b, auto c) { context->VSGetConstantBuffers(a, b, c); },
                [&](auto a, auto b, auto c) { context->VSGetShaderResources(a, b, c); },
                [&](auto a, auto b, auto c) { context->VSGetSamplers(a, b, c); })},
            {"ps", GraphicsStage<ID3D11PixelShader>("ps",
                [&](auto a, auto b, auto c) { context->PSGetShader(a, b, c); },
                [&](auto a, auto b, auto c) { context->PSGetConstantBuffers(a, b, c); },
                [&](auto a, auto b, auto c) { context->PSGetShaderResources(a, b, c); },
                [&](auto a, auto b, auto c) { context->PSGetSamplers(a, b, c); })},
            {"gs", GraphicsStage<ID3D11GeometryShader>("gs",
                [&](auto a, auto b, auto c) { context->GSGetShader(a, b, c); },
                [&](auto a, auto b, auto c) { context->GSGetConstantBuffers(a, b, c); },
                [&](auto a, auto b, auto c) { context->GSGetShaderResources(a, b, c); },
                [&](auto a, auto b, auto c) { context->GSGetSamplers(a, b, c); })},
            {"hs", GraphicsStage<ID3D11HullShader>("hs",
                [&](auto a, auto b, auto c) { context->HSGetShader(a, b, c); },
                [&](auto a, auto b, auto c) { context->HSGetConstantBuffers(a, b, c); },
                [&](auto a, auto b, auto c) { context->HSGetShaderResources(a, b, c); },
                [&](auto a, auto b, auto c) { context->HSGetSamplers(a, b, c); })},
            {"ds", GraphicsStage<ID3D11DomainShader>("ds",
                [&](auto a, auto b, auto c) { context->DSGetShader(a, b, c); },
                [&](auto a, auto b, auto c) { context->DSGetConstantBuffers(a, b, c); },
                [&](auto a, auto b, auto c) { context->DSGetShaderResources(a, b, c); },
                [&](auto a, auto b, auto c) { context->DSGetSamplers(a, b, c); })},
            {"cs", GraphicsStage<ID3D11ComputeShader>("cs",
                [&](auto a, auto b, auto c) { context->CSGetShader(a, b, c); },
                [&](auto a, auto b, auto c) { context->CSGetConstantBuffers(a, b, c); },
                [&](auto a, auto b, auto c) { context->CSGetShaderResources(a, b, c); },
                [&](auto a, auto b, auto c) { context->CSGetSamplers(a, b, c); })},
        };

        ID3D11RasterizerState* rawRasterizer = nullptr; context->RSGetState(&rawRasterizer);
        ComPtr<ID3D11RasterizerState> rasterizer; rasterizer.Attach(rawRasterizer);
        Json rasterizerValue = nullptr;
        if (rasterizer) { D3D11_RASTERIZER_DESC descriptor{}; rasterizer->GetDesc(&descriptor);
            rasterizerValue = {{"object", Pointer(rasterizer.Get())}, {"descriptor", RasterizerDescriptor(descriptor)}}; }
        UINT viewportCount = 0; context->RSGetViewports(&viewportCount, nullptr);
        std::vector<D3D11_VIEWPORT> viewports(viewportCount); if (viewportCount) context->RSGetViewports(&viewportCount, viewports.data());
        Json viewportValues = Json::array(); for (const auto& value : viewports) viewportValues.push_back({
            {"top_left_x", value.TopLeftX}, {"top_left_y", value.TopLeftY}, {"width", value.Width}, {"height", value.Height},
            {"min_depth", value.MinDepth}, {"max_depth", value.MaxDepth}});
        UINT scissorCount = 0; context->RSGetScissorRects(&scissorCount, nullptr);
        std::vector<D3D11_RECT> scissors(scissorCount); if (scissorCount) context->RSGetScissorRects(&scissorCount, scissors.data());
        Json scissorValues = Json::array(); for (const auto& value : scissors) scissorValues.push_back({
            {"left", value.left}, {"top", value.top}, {"right", value.right}, {"bottom", value.bottom}});
        pipeline["rasterizer"] = {{"state", std::move(rasterizerValue)}, {"viewports", std::move(viewportValues)},
            {"scissors", std::move(scissorValues)}};

        std::array<ID3D11RenderTargetView*, D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT> rawRtvs{};
        ID3D11DepthStencilView* rawDsv = nullptr; context->OMGetRenderTargets(static_cast<UINT>(rawRtvs.size()), rawRtvs.data(), &rawDsv);
        Json rtvs = Json::array();
        for (UINT slot = 0; slot < rawRtvs.size(); ++slot) if (rawRtvs[slot]) {
            D3D11_RENDER_TARGET_VIEW_DESC descriptor{}; rawRtvs[slot]->GetDesc(&descriptor);
            ComPtr<ID3D11Resource> resource; rawRtvs[slot]->GetResource(&resource);
            rtvs.push_back({{"slot", slot}, {"object", Pointer(rawRtvs[slot])},
                {"descriptor", RawDescriptor(descriptor, {{"format", static_cast<unsigned>(descriptor.Format)},
                    {"view_dimension", static_cast<unsigned>(descriptor.ViewDimension)}})},
                {"resource", ResourceObject(resource.Get())}}); rawRtvs[slot]->Release();
        }
        ComPtr<ID3D11DepthStencilView> dsv; dsv.Attach(rawDsv);
        Json dsvValue = nullptr;
        if (dsv) { D3D11_DEPTH_STENCIL_VIEW_DESC descriptor{}; dsv->GetDesc(&descriptor);
            ComPtr<ID3D11Resource> resource; dsv->GetResource(&resource);
            dsvValue = {{"object", Pointer(dsv.Get())}, {"descriptor", RawDescriptor(descriptor,
                {{"format", static_cast<unsigned>(descriptor.Format)}, {"view_dimension", static_cast<unsigned>(descriptor.ViewDimension)},
                 {"flags", descriptor.Flags}})}, {"resource", ResourceObject(resource.Get())}}; }
        ID3D11BlendState* rawBlend = nullptr; FLOAT blendFactor[4]{}; UINT sampleMask = 0;
        context->OMGetBlendState(&rawBlend, blendFactor, &sampleMask); ComPtr<ID3D11BlendState> blend; blend.Attach(rawBlend);
        Json blendValue = nullptr; if (blend) { D3D11_BLEND_DESC descriptor{}; blend->GetDesc(&descriptor);
            blendValue = {{"object", Pointer(blend.Get())}, {"descriptor", RawDescriptor(descriptor)}}; }
        ID3D11DepthStencilState* rawDepth = nullptr; UINT stencilRef = 0;
        context->OMGetDepthStencilState(&rawDepth, &stencilRef); ComPtr<ID3D11DepthStencilState> depth; depth.Attach(rawDepth);
        Json depthValue = nullptr; if (depth) { D3D11_DEPTH_STENCIL_DESC descriptor{}; depth->GetDesc(&descriptor);
            depthValue = {{"object", Pointer(depth.Get())}, {"descriptor", RawDescriptor(descriptor)}}; }
        pipeline["output_merger"] = {{"rtvs", std::move(rtvs)}, {"dsv", std::move(dsvValue)},
            {"blend_state", std::move(blendValue)}, {"blend_factor", Json::array({blendFactor[0], blendFactor[1], blendFactor[2], blendFactor[3]})},
            {"sample_mask", sampleMask}, {"depth_stencil_state", std::move(depthValue)}, {"stencil_ref", stencilRef}};
        return pipeline;
    }

    static bool BlockCompressed(DXGI_FORMAT format) noexcept {
        return (format >= DXGI_FORMAT_BC1_TYPELESS && format <= DXGI_FORMAT_BC5_SNORM) ||
            (format >= DXGI_FORMAT_BC6H_TYPELESS && format <= DXGI_FORMAT_BC7_UNORM_SRGB);
    }

    static UINT MipExtent(UINT value, UINT mip) noexcept { return std::max(1U, value >> mip); }

    Json AddDump(CaptureJob& job, const char* phase, ID3D11Resource* source) {
        Require(source != nullptr, "D3D11 resource dump source is null");
        ComPtr<ID3D11Device> device;
        job.context->GetDevice(&device);
        D3D11_RESOURCE_DIMENSION dimension{};
        source->GetType(&dimension);
        ComPtr<ID3D11Resource> staging;
        UINT mipLevels = 1, arraySize = 1, width = 1, height = 1, depth = 1;
        DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN;
        Json descriptor;
        if (dimension == D3D11_RESOURCE_DIMENSION_BUFFER) {
            ComPtr<ID3D11Buffer> typedSource; Require(SUCCEEDED(source->QueryInterface(IID_PPV_ARGS(&typedSource))), "buffer query failed");
            D3D11_BUFFER_DESC value{}; typedSource->GetDesc(&value); descriptor = BufferDescriptor(value); width = value.ByteWidth;
            D3D11_BUFFER_DESC copy = value; copy.Usage = D3D11_USAGE_STAGING; copy.BindFlags = 0;
            copy.CPUAccessFlags = D3D11_CPU_ACCESS_READ; copy.MiscFlags = 0; copy.StructureByteStride = 0;
            ComPtr<ID3D11Buffer> typedStaging; Require(SUCCEEDED(device->CreateBuffer(&copy, nullptr, &typedStaging)), "buffer staging creation failed");
            Require(SUCCEEDED(typedStaging.As(&staging)), "buffer staging resource query failed");
        } else if (dimension == D3D11_RESOURCE_DIMENSION_TEXTURE1D) {
            ComPtr<ID3D11Texture1D> typedSource; Require(SUCCEEDED(source->QueryInterface(IID_PPV_ARGS(&typedSource))), "texture1d query failed");
            D3D11_TEXTURE1D_DESC value{}; typedSource->GetDesc(&value); descriptor = RawDescriptor(value);
            width = value.Width; mipLevels = value.MipLevels; arraySize = value.ArraySize; format = value.Format;
            D3D11_TEXTURE1D_DESC copy = value; copy.Usage = D3D11_USAGE_STAGING; copy.BindFlags = 0;
            copy.CPUAccessFlags = D3D11_CPU_ACCESS_READ; copy.MiscFlags = 0;
            ComPtr<ID3D11Texture1D> typedStaging; Require(SUCCEEDED(device->CreateTexture1D(&copy, nullptr, &typedStaging)), "texture1d staging creation failed");
            Require(SUCCEEDED(typedStaging.As(&staging)), "texture1d staging resource query failed");
        } else if (dimension == D3D11_RESOURCE_DIMENSION_TEXTURE2D) {
            ComPtr<ID3D11Texture2D> typedSource; Require(SUCCEEDED(source->QueryInterface(IID_PPV_ARGS(&typedSource))), "texture2d query failed");
            D3D11_TEXTURE2D_DESC value{}; typedSource->GetDesc(&value); descriptor = Texture2DDescriptor(value);
            Require(value.SampleDesc.Count == 1, "multisampled resource readback requires explicit resolve semantics");
            width = value.Width; height = value.Height; mipLevels = value.MipLevels; arraySize = value.ArraySize; format = value.Format;
            D3D11_TEXTURE2D_DESC copy = value; copy.Usage = D3D11_USAGE_STAGING; copy.BindFlags = 0;
            copy.CPUAccessFlags = D3D11_CPU_ACCESS_READ; copy.MiscFlags = 0;
            ComPtr<ID3D11Texture2D> typedStaging; Require(SUCCEEDED(device->CreateTexture2D(&copy, nullptr, &typedStaging)), "texture2d staging creation failed");
            Require(SUCCEEDED(typedStaging.As(&staging)), "texture2d staging resource query failed");
        } else if (dimension == D3D11_RESOURCE_DIMENSION_TEXTURE3D) {
            ComPtr<ID3D11Texture3D> typedSource; Require(SUCCEEDED(source->QueryInterface(IID_PPV_ARGS(&typedSource))), "texture3d query failed");
            D3D11_TEXTURE3D_DESC value{}; typedSource->GetDesc(&value); descriptor = RawDescriptor(value);
            width = value.Width; height = value.Height; depth = value.Depth; mipLevels = value.MipLevels; format = value.Format;
            D3D11_TEXTURE3D_DESC copy = value; copy.Usage = D3D11_USAGE_STAGING; copy.BindFlags = 0;
            copy.CPUAccessFlags = D3D11_CPU_ACCESS_READ; copy.MiscFlags = 0;
            ComPtr<ID3D11Texture3D> typedStaging; Require(SUCCEEDED(device->CreateTexture3D(&copy, nullptr, &typedStaging)), "texture3d staging creation failed");
            Require(SUCCEEDED(typedStaging.As(&staging)), "texture3d staging resource query failed");
        } else throw std::runtime_error("unsupported D3D11 resource dimension");
        job.context->CopyResource(staging.Get(), source);
        Json subresources = Json::array();
        const UINT count = dimension == D3D11_RESOURCE_DIMENSION_TEXTURE3D ? mipLevels : mipLevels * arraySize;
        for (UINT subresource = 0; subresource < count; ++subresource) {
            D3D11_MAPPED_SUBRESOURCE mapped{};
            Require(SUCCEEDED(job.context->Map(staging.Get(), subresource, D3D11_MAP_READ, 0, &mapped)), "staging resource map failed");
            const UINT mip = subresource % mipLevels;
            const UINT rows = dimension == D3D11_RESOURCE_DIMENSION_BUFFER || dimension == D3D11_RESOURCE_DIMENSION_TEXTURE1D ? 1U :
                BlockCompressed(format) ? std::max(1U, (MipExtent(height, mip) + 3) / 4) : MipExtent(height, mip);
            const UINT slices = dimension == D3D11_RESOURCE_DIMENSION_TEXTURE3D ? MipExtent(depth, mip) : 1U;
            const size_t rowPitch = dimension == D3D11_RESOURCE_DIMENSION_BUFFER ? width : mapped.RowPitch;
            const size_t depthPitch = dimension == D3D11_RESOURCE_DIMENSION_BUFFER ? width :
                dimension == D3D11_RESOURCE_DIMENSION_TEXTURE1D ? mapped.RowPitch : mapped.DepthPitch ? mapped.DepthPitch : rowPitch * rows;
            const size_t byteCount = dimension == D3D11_RESOURCE_DIMENSION_BUFFER ? width : depthPitch * slices;
            Bytes bytes(byteCount);
            if (byteCount) std::memcpy(bytes.data(), mapped.pData, byteCount);
            job.context->Unmap(staging.Get(), subresource);
            const std::string object = Pointer(source).get<std::string>();
            std::string portableObject = object; portableObject.erase(std::remove(portableObject.begin(), portableObject.end(), 'x'), portableObject.end());
            const fs::path relative = fs::path("resources") / (std::string(phase) + "-" + portableObject + "-sub" +
                std::to_string(subresource) + ".bin");
            const std::u8string encoded = relative.generic_u8string();
            const std::string portable(reinterpret_cast<const char*>(encoded.data()), encoded.size());
            const std::string digest = Sha(bytes.data(), bytes.size());
            subresources.push_back({{"subresource", subresource}, {"mip", mip}, {"row_pitch", rowPitch},
                {"depth_pitch", depthPitch}, {"rows", rows}, {"slices", slices}, {"path", portable},
                {"size_bytes", bytes.size()}, {"sha256", digest}, {"lossless", true}});
            job.outputs.push_back({relative, std::move(bytes)});
        }
        return {{"phase", phase}, {"object", Pointer(source)}, {"dimension", static_cast<unsigned>(dimension)},
            {"descriptor", std::move(descriptor)}, {"subresources", std::move(subresources)}};
    }

    void CollectResources(ID3D11DeviceContext* context, std::vector<ComPtr<ID3D11Resource>>& inputs,
                          std::vector<ComPtr<ID3D11Resource>>& outputs) const {
        std::unordered_set<ID3D11Resource*> seenInputs, seenOutputs;
        auto add = [](auto* object, auto& destination, auto& seen) {
            if (!object) return;
            ComPtr<ID3D11Resource> resource;
            if constexpr (std::is_base_of_v<ID3D11Resource, std::remove_pointer_t<decltype(object)>>) {
                object->QueryInterface(IID_PPV_ARGS(&resource));
            } else object->GetResource(&resource);
            if (resource && seen.insert(resource.Get()).second) destination.push_back(resource);
        };
        std::array<ID3D11Buffer*, D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT> vertexBuffers{};
        context->IAGetVertexBuffers(0, static_cast<UINT>(vertexBuffers.size()), vertexBuffers.data(), nullptr, nullptr);
        for (auto* value : vertexBuffers) { add(value, inputs, seenInputs); if (value) value->Release(); }
        ID3D11Buffer* index = nullptr; context->IAGetIndexBuffer(&index, nullptr, nullptr);
        add(index, inputs, seenInputs); if (index) index->Release();
        auto collectStage = [&](auto getBuffers, auto getSrvs) {
            std::array<ID3D11Buffer*, D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT> buffers{};
            getBuffers(0, static_cast<UINT>(buffers.size()), buffers.data());
            for (auto* value : buffers) { add(value, inputs, seenInputs); if (value) value->Release(); }
            std::array<ID3D11ShaderResourceView*, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT> views{};
            getSrvs(0, static_cast<UINT>(views.size()), views.data());
            for (auto* value : views) { add(value, inputs, seenInputs); if (value) value->Release(); }
        };
        collectStage([&](auto a, auto b, auto c) { context->VSGetConstantBuffers(a, b, c); },
            [&](auto a, auto b, auto c) { context->VSGetShaderResources(a, b, c); });
        collectStage([&](auto a, auto b, auto c) { context->PSGetConstantBuffers(a, b, c); },
            [&](auto a, auto b, auto c) { context->PSGetShaderResources(a, b, c); });
        collectStage([&](auto a, auto b, auto c) { context->GSGetConstantBuffers(a, b, c); },
            [&](auto a, auto b, auto c) { context->GSGetShaderResources(a, b, c); });
        collectStage([&](auto a, auto b, auto c) { context->HSGetConstantBuffers(a, b, c); },
            [&](auto a, auto b, auto c) { context->HSGetShaderResources(a, b, c); });
        collectStage([&](auto a, auto b, auto c) { context->DSGetConstantBuffers(a, b, c); },
            [&](auto a, auto b, auto c) { context->DSGetShaderResources(a, b, c); });
        std::array<ID3D11Buffer*, D3D11_SO_BUFFER_SLOT_COUNT> streamOutput{};
        context->SOGetTargets(static_cast<UINT>(streamOutput.size()), streamOutput.data());
        for (auto* value : streamOutput) { add(value, outputs, seenOutputs); if (value) value->Release(); }
        std::array<ID3D11RenderTargetView*, D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT> rtvs{};
        ID3D11DepthStencilView* dsv = nullptr;
        context->OMGetRenderTargets(static_cast<UINT>(rtvs.size()), rtvs.data(), &dsv);
        for (auto* value : rtvs) { add(value, outputs, seenOutputs); if (value) value->Release(); }
        add(dsv, outputs, seenOutputs); if (dsv) dsv->Release();
    }

    CaptureJob* ObserveDraw(Kind kind, const std::array<void*, 12>& arguments) {
        drawsObserved.fetch_add(1, std::memory_order_relaxed);
        if (!armed.load(std::memory_order_acquire) || capturesReserved.load(std::memory_order_acquire) >= maxCaptures) return nullptr;
        auto* context = static_cast<ID3D11DeviceContext*>(arguments[0]);
        if (!context) return nullptr;
        ComPtr<ID3D11PixelShader> pixelShader;
        context->PSGetShader(&pixelShader, nullptr, nullptr);
        ComPtr<ID3D11VertexShader> vertexShader;
        context->VSGetShader(&vertexShader, nullptr, nullptr);
        std::string psSha, vsSha;
        size_t bytecodeSize = 0, vertexBytecodeSize = 0;
        {
            std::lock_guard lock(mutex);
            auto found = shaders.find(pixelShader.Get());
            if (found != shaders.end()) {
                psSha = found->second.sha256;
                bytecodeSize = found->second.bytecode.size();
            }
            found = shaders.find(vertexShader.Get());
            if (found != shaders.end()) {
                vsSha = found->second.sha256;
                vertexBytecodeSize = found->second.bytecode.size();
            }
        }
        if (!requiredPsSha256.empty() && psSha != requiredPsSha256) return nullptr;
        if (!requiredVsSha256.empty() && vsSha != requiredVsSha256) return nullptr;
        matchingDraws.fetch_add(1, std::memory_order_relaxed);
        const uint64_t captureIndex = capturesReserved.fetch_add(1, std::memory_order_acq_rel);
        if (captureIndex >= maxCaptures) return nullptr;
        auto job = std::make_unique<CaptureJob>();
        job->context = context;
        const std::string suffix = std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++armCounter);
        job->suffix = suffix;
        job->catalog = {
            {"schema", "uc.d3d11-draw-catalog.v1"},
            {"status", "pipeline-identity-qualified-resource-snapshot-pending"},
            {"captured_utc", WallClockUtc()},
            {"arm_label", armLabel},
            {"draw", {{"call", KindName(kind)}, {"arguments", DrawArguments(kind, arguments)}}},
            {"pixel_shader", {{"object", Pointer(pixelShader.Get())}, {"sha256", psSha},
                {"bytecode_size", bytecodeSize}}},
            {"vertex_shader", {{"object", Pointer(vertexShader.Get())}, {"sha256", vsSha},
                {"bytecode_size", vertexBytecodeSize}}},
            {"capture_index", captureIndex}, {"catalog_only", catalogOnly},
            {"startup_ledger", {{"shader_objects", shadersObserved.load()},
                {"input_layout_objects", layoutsObserved.load()}}},
            {"pipeline", PipelineIdentity(context)}, {"resource_snapshots", Json::array()},
            {"process", {{"pid", GetCurrentProcessId()}}},
        };
        if (!catalogOnly) {
            std::vector<ComPtr<ID3D11Resource>> inputs;
            CollectResources(context, inputs, job->outputResources);
            for (auto& input : inputs) job->catalog["resource_snapshots"].push_back(AddDump(*job, "before-input", input.Get()));
            for (auto& output : job->outputResources) job->catalog["resource_snapshots"].push_back(AddDump(*job, "before-output", output.Get()));
        }
        return job.release();
    }

    void CompleteDraw(std::unique_ptr<CaptureJob> job) {
        for (auto& output : job->outputResources)
            job->catalog["resource_snapshots"].push_back(AddDump(*job, "after-output", output.Get()));
        job->catalog["status"] = catalogOnly ? "pipeline-identity-cataloged" :
            "pipeline-and-lossless-resource-snapshots-captured";
        std::lock_guard lock(mutex);
        for (auto& output : job->outputs) pendingOutputs.push_back(std::move(output));
        pendingFiles.push_back({{"relative", "draw-catalog-" + job->suffix + ".json"}, {"content", std::move(job->catalog)}});
        if (capturesReserved.load(std::memory_order_acquire) >= maxCaptures)
            captured.store(true, std::memory_order_release);
    }

    void Tick() {
        if (!exportHooksReady.load(std::memory_order_acquire)) AttachExports();
        std::deque<Json> files;
        std::deque<PendingOutput> outputs;
        {
            std::lock_guard lock(mutex);
            files.swap(pendingFiles);
            outputs.swap(pendingOutputs);
        }
        if (files.empty() && outputs.empty()) return;
        Require(fs::create_directories(outputRoot) || fs::is_directory(outputRoot),
            "D3D11 observer output directory creation failed");
        for (auto& output : outputs) {
            const fs::path destination = outputRoot / output.relative;
            Require(fs::create_directories(destination.parent_path()) || fs::is_directory(destination.parent_path()),
                "D3D11 observer artifact directory creation failed");
            NewFile(destination, output.bytes.data(), output.bytes.size());
        }
        for (auto& file : files) {
            const fs::path destination = outputRoot / Utf8(file.at("relative").get<std::string>());
            std::string text = file.at("content").dump(2);
            text.push_back('\n');
            NewFile(destination, text.data(), text.size());
        }
    }

    Json Status() const {
        std::lock_guard lock(mutex);
        return {
            {"enabled", true}, {"ready", exportHooksReady.load()}, {"armed", armed.load()},
            {"captured", captured.load()}, {"arm_label", armLabel}, {"output_root", outputRoot.string()},
            {"pixel_shader_sha256", requiredPsSha256}, {"vertex_shader_sha256", requiredVsSha256},
            {"catalog_only", catalogOnly}, {"max_captures", maxCaptures}, {"captures_reserved", capturesReserved.load()},
            {"frames_observed", frames.load()},
            {"draws_observed", drawsObserved.load()}, {"matching_draws", matchingDraws.load()},
            {"shaders_observed", shadersObserved.load()}, {"shader_objects_resident", shaders.size()},
            {"input_layouts_observed", layoutsObserved.load()}, {"input_layout_objects_resident", layouts.size()},
            {"devices_observed", devices.size()}, {"contexts_observed", contexts.size()},
            {"swapchains_observed", swapchains.size()}, {"hook_targets", targets.size()}, {"error", error},
        };
    }

    Json Arm(std::string label) {
        Require(exportHooksReady.load(std::memory_order_acquire), "D3D11 observer is not ready");
        Require(!label.empty(), "D3D11 capture arm label is required");
        std::lock_guard lock(mutex);
        armLabel = std::move(label);
        captured.store(false, std::memory_order_release);
        capturesReserved.store(0, std::memory_order_release);
        armed.store(true, std::memory_order_release);
        return {{"armed", true}, {"label", armLabel}, {"pixel_shader_sha256", requiredPsSha256},
            {"vertex_shader_sha256", requiredVsSha256}, {"catalog_only", catalogOnly}, {"max_captures", maxCaptures},
            {"output_root", outputRoot.string()}};
    }
};

Observer::Observer(GumInterceptor* interceptor, fs::path observerDirectory, Json configuration)
    : impl_(std::make_unique<Impl>(interceptor, std::move(observerDirectory), std::move(configuration))) {}
Observer::~Observer() = default;
void Observer::Tick() noexcept { try { impl_->Tick(); } catch (const std::exception& error) { impl_->SetError(error.what()); } }
Json Observer::Status() const { return impl_->Status(); }
Json Observer::Arm(const std::string& label) { return impl_->Arm(label); }
bool Observer::Ready() const noexcept { return impl_->exportHooksReady.load(std::memory_order_acquire); }
bool Observer::Captured() const noexcept { return impl_->captured.load(std::memory_order_acquire); }

}
