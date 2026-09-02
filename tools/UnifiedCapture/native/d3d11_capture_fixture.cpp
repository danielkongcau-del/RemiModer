#include "d3d11_package.h"
#include <dxgi.h>
#include <wrl/client.h>
#include <iostream>
#if __has_include("renderdoc_app.h")
#include "renderdoc_app.h"
#define UC_HAS_RENDERDOC_APP_HEADER 1
#endif

using Microsoft::WRL::ComPtr;
using uc::Bytes;
using uc::Json;
using uc::Require;
namespace d11 = uc::d3d11;

static LRESULT CALLBACK FixtureWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    return DefWindowProcW(window, message, wparam, lparam);
}

struct HiddenWindow {
    HINSTANCE instance = GetModuleHandleW(nullptr);
    const wchar_t* className = L"UnifiedCaptureD3D11FixtureWindow";
    HWND handle = nullptr;
    HiddenWindow() {
        WNDCLASSW windowClass{};
        windowClass.lpfnWndProc = FixtureWindowProc;
        windowClass.hInstance = instance;
        windowClass.lpszClassName = className;
        Require(RegisterClassW(&windowClass) || GetLastError() == ERROR_CLASS_ALREADY_EXISTS,
                "fixture window class registration failed");
        handle = CreateWindowExW(0, className, L"UnifiedCapture D3D11 fixture", WS_OVERLAPPED,
            0, 0, 16, 16, nullptr, nullptr, instance, nullptr);
        Require(handle != nullptr, "hidden fixture window creation failed");
    }
    ~HiddenWindow() {
        if (handle) DestroyWindow(handle);
        UnregisterClassW(className, instance);
    }
};

struct OptionalRenderDocCapture {
#if defined(UC_HAS_RENDERDOC_APP_HEADER)
    RENDERDOC_API_1_6_0* api = nullptr;
#endif
    ID3D11Device* device = nullptr;
    HWND window = nullptr;
    bool active = false;
    OptionalRenderDocCapture(ID3D11Device* capturedDevice, HWND capturedWindow)
        : device(capturedDevice), window(capturedWindow) {
#if defined(UC_HAS_RENDERDOC_APP_HEADER)
        HMODULE module = GetModuleHandleW(L"renderdoc.dll");
        if (!module) return;
        auto getApi = reinterpret_cast<pRENDERDOC_GetAPI>(GetProcAddress(module, "RENDERDOC_GetAPI"));
        Require(getApi && getApi(eRENDERDOC_API_Version_1_6_0, reinterpret_cast<void**>(&api)) == 1,
                "injected RenderDoc API negotiation failed");
        api->StartFrameCapture(device, window);
        api->SetCaptureTitle("UnifiedCapture owned D3D11 fixture");
        active = true;
#endif
    }
    void End() {
#if defined(UC_HAS_RENDERDOC_APP_HEADER)
        if (active) {
            Require(api->EndFrameCapture(device, window) == 1, "RenderDoc frame capture failed");
            active = false;
        }
#endif
    }
    ~OptionalRenderDocCapture() {
#if defined(UC_HAS_RENDERDOC_APP_HEADER)
        if (active) api->DiscardFrameCapture(device, window);
#endif
    }
};

static ComPtr<ID3DBlob> Compile(const char* source, const char* profile) {
    ComPtr<ID3DBlob> bytecode, errors;
    const HRESULT result = D3DCompile(source, std::strlen(source), "owned-d3d11-fixture", nullptr, nullptr,
        "main", profile, D3DCOMPILE_ENABLE_STRICTNESS | D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &bytecode, &errors);
    if (FAILED(result)) {
        std::string message = errors ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize()) :
            "shader compilation failed";
        throw std::runtime_error(message);
    }
    return bytecode;
}

static Json Slot(unsigned slot, const char* id) {
    return {{"slot", slot}, {"object_id", id}};
}

static Json Stage(const char* shader, Json constantBuffers = Json::array()) {
    return {{"shader_id", shader}, {"class_instance_ids", Json::array()},
            {"constant_buffers", std::move(constantBuffers)}, {"srvs", Json::array()},
            {"samplers", Json::array()}, {"uavs", Json::array()}};
}

int wmain(int argc, wchar_t** argv) try {
    Require(argc == 2, "usage: D3D11CaptureFixture.exe <new-package-directory>");
    constexpr unsigned width = 16, height = 16;
    d11::PackageWriter writer(argv[1]);

    D3D_FEATURE_LEVEL level{};
    const D3D_FEATURE_LEVEL requested[] = {D3D_FEATURE_LEVEL_11_0};
    HiddenWindow window;
    DXGI_SWAP_CHAIN_DESC swapDesc{};
    swapDesc.BufferDesc.Width = width;
    swapDesc.BufferDesc.Height = height;
    swapDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapDesc.SampleDesc.Count = 1;
    swapDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapDesc.BufferCount = 1;
    swapDesc.OutputWindow = window.handle;
    swapDesc.Windowed = TRUE;
    swapDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    ComPtr<IDXGISwapChain> swapchain;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    Require(SUCCEEDED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, requested,
        static_cast<UINT>(std::size(requested)), D3D11_SDK_VERSION, &swapDesc, &swapchain, &device, &level, &context)),
        "D3D11 WARP device/swapchain creation failed");

    const char* vsSource = R"(
cbuffer FixtureConstants : register(b0) { float4 scaleBias; };
struct Input { float2 position : POSITION; };
struct Output { float4 position : SV_POSITION; };
Output main(Input input) {
    Output output;
    output.position = float4(input.position * scaleBias.xy + scaleBias.zw, 0.0, 1.0);
    return output;
})";
    const char* psSource = R"(
float4 main() : SV_Target0 { return float4(1.0, 0.25, 0.5, 1.0); }
)";
    ComPtr<ID3DBlob> vsBytes = Compile(vsSource, "vs_5_0");
    ComPtr<ID3DBlob> psBytes = Compile(psSource, "ps_5_0");

    const float vertices[][2] = {{-1.0f, -1.0f}, {-1.0f, 3.0f}, {3.0f, -1.0f}};
    const float constants[4] = {1.0f, 1.0f, 0.0f, 0.0f};
    D3D11_BUFFER_DESC vbDesc{};
    vbDesc.ByteWidth = sizeof(vertices);
    vbDesc.Usage = D3D11_USAGE_IMMUTABLE;
    vbDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    D3D11_SUBRESOURCE_DATA vbData{vertices, 0, 0};
    ComPtr<ID3D11Buffer> vertexBuffer;
    Require(SUCCEEDED(device->CreateBuffer(&vbDesc, &vbData, &vertexBuffer)), "vertex buffer creation failed");

    D3D11_BUFFER_DESC cbDesc{};
    cbDesc.ByteWidth = sizeof(constants);
    cbDesc.Usage = D3D11_USAGE_IMMUTABLE;
    cbDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    D3D11_SUBRESOURCE_DATA cbData{constants, 0, 0};
    ComPtr<ID3D11Buffer> constantBuffer;
    Require(SUCCEEDED(device->CreateBuffer(&cbDesc, &cbData, &constantBuffer)), "constant buffer creation failed");

    D3D11_TEXTURE2D_DESC targetDesc{};
    targetDesc.Width = width;
    targetDesc.Height = height;
    targetDesc.MipLevels = 1;
    targetDesc.ArraySize = 1;
    targetDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    targetDesc.SampleDesc.Count = 1;
    targetDesc.Usage = D3D11_USAGE_DEFAULT;
    targetDesc.BindFlags = D3D11_BIND_RENDER_TARGET;
    ComPtr<ID3D11Texture2D> target;
    Require(SUCCEEDED(device->CreateTexture2D(&targetDesc, nullptr, &target)), "render target creation failed");

    D3D11_RENDER_TARGET_VIEW_DESC rtvDesc{};
    rtvDesc.Format = targetDesc.Format;
    rtvDesc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
    rtvDesc.Texture2D.MipSlice = 0;
    ComPtr<ID3D11RenderTargetView> targetView;
    Require(SUCCEEDED(device->CreateRenderTargetView(target.Get(), &rtvDesc, &targetView)), "RTV creation failed");

    ComPtr<ID3D11VertexShader> vertexShader;
    Require(SUCCEEDED(device->CreateVertexShader(vsBytes->GetBufferPointer(), vsBytes->GetBufferSize(), nullptr,
        &vertexShader)), "vertex shader creation failed");
    ComPtr<ID3D11PixelShader> pixelShader;
    Require(SUCCEEDED(device->CreatePixelShader(psBytes->GetBufferPointer(), psBytes->GetBufferSize(), nullptr,
        &pixelShader)), "pixel shader creation failed");
    const D3D11_INPUT_ELEMENT_DESC inputElements[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
    };
    ComPtr<ID3D11InputLayout> inputLayout;
    Require(SUCCEEDED(device->CreateInputLayout(inputElements, static_cast<UINT>(std::size(inputElements)),
        vsBytes->GetBufferPointer(), vsBytes->GetBufferSize(), &inputLayout)), "input layout creation failed");

    D3D11_RASTERIZER_DESC rasterizerDesc{};
    rasterizerDesc.FillMode = D3D11_FILL_SOLID;
    rasterizerDesc.CullMode = D3D11_CULL_NONE;
    rasterizerDesc.DepthClipEnable = TRUE;
    ComPtr<ID3D11RasterizerState> rasterizer;
    Require(SUCCEEDED(device->CreateRasterizerState(&rasterizerDesc, &rasterizer)), "rasterizer creation failed");

    const UINT stride = sizeof(vertices[0]), offset = 0;
    const D3D11_VIEWPORT viewport{0.0f, 0.0f, static_cast<float>(width), static_cast<float>(height), 0.0f, 1.0f};
    OptionalRenderDocCapture renderDocCapture(device.Get(), window.handle);
    context->IASetInputLayout(inputLayout.Get());
    ID3D11Buffer* vb = vertexBuffer.Get();
    context->IASetVertexBuffers(0, 1, &vb, &stride, &offset);
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(vertexShader.Get(), nullptr, 0);
    ID3D11Buffer* cb = constantBuffer.Get();
    context->VSSetConstantBuffers(0, 1, &cb);
    context->PSSetShader(pixelShader.Get(), nullptr, 0);
    context->RSSetState(rasterizer.Get());
    context->RSSetViewports(1, &viewport);
    ID3D11RenderTargetView* rtv = targetView.Get();
    context->OMSetRenderTargets(1, &rtv, nullptr);
    const float clear[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    context->ClearRenderTargetView(targetView.Get(), clear);
    context->Draw(3, 0);
    renderDocCapture.End();
    Require(SUCCEEDED(swapchain->Present(0, 0)), "fixture Present failed");

    D3D11_TEXTURE2D_DESC stagingDesc = targetDesc;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.BindFlags = 0;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ComPtr<ID3D11Texture2D> staging;
    Require(SUCCEEDED(device->CreateTexture2D(&stagingDesc, nullptr, &staging)), "staging creation failed");
    context->CopyResource(staging.Get(), target.Get());
    D3D11_MAPPED_SUBRESOURCE mapped{};
    Require(SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped)), "target readback failed");
    Bytes reference(width * height * 4);
    for (unsigned row = 0; row < height; ++row)
        std::memcpy(reference.data() + row * width * 4,
                    static_cast<const unsigned char*>(mapped.pData) + row * mapped.RowPitch, width * 4);
    context->Unmap(staging.Get(), 0);

    writer.AddArtifact("artifact.vs", "dxbc", L"artifacts/vs.dxbc", vsBytes->GetBufferPointer(), vsBytes->GetBufferSize());
    writer.AddArtifact("artifact.ps", "dxbc", L"artifacts/ps.dxbc", psBytes->GetBufferPointer(), psBytes->GetBufferSize());
    writer.AddArtifact("artifact.vb", "resource_initial_data", L"artifacts/vb.bin", vertices, sizeof(vertices));
    writer.AddArtifact("artifact.cb", "resource_initial_data", L"artifacts/cb.bin", constants, sizeof(constants));
    writer.AddArtifact("artifact.reference", "reference_attachment", L"reference/gbuffer0.bin",
        reference.data(), reference.size());

    wchar_t executablePath[32768]{};
    const DWORD executableLength = GetModuleFileNameW(nullptr, executablePath, static_cast<DWORD>(std::size(executablePath)));
    Require(executableLength && executableLength < std::size(executablePath), "fixture executable path unavailable");
    ComPtr<IDXGIDevice> dxgiDevice;
    Require(SUCCEEDED(device.As(&dxgiDevice)), "DXGI device query failed");
    ComPtr<IDXGIAdapter> adapter;
    Require(SUCCEEDED(dxgiDevice->GetAdapter(&adapter)), "DXGI adapter query failed");
    DXGI_ADAPTER_DESC adapterDesc{};
    Require(SUCCEEDED(adapter->GetDesc(&adapterDesc)), "DXGI adapter descriptor failed");

    const std::string vsHash = uc::Sha(vsBytes->GetBufferPointer(), vsBytes->GetBufferSize());
    const std::string psHash = uc::Sha(psBytes->GetBufferPointer(), psBytes->GetBufferSize());
    Json resources = Json::array({
        {{"id", "res.vb"}, {"kind", "buffer"}, {"descriptor", d11::BufferDescriptor(vbDesc)},
         {"content_policy", "initial_data"}, {"initial_data", Json::array({{{"subresource", 0},
             {"artifact_id", "artifact.vb"}, {"row_pitch", sizeof(vertices)}, {"depth_pitch", sizeof(vertices)}}})}},
        {{"id", "res.cb"}, {"kind", "buffer"}, {"descriptor", d11::BufferDescriptor(cbDesc)},
         {"content_policy", "initial_data"}, {"initial_data", Json::array({{{"subresource", 0},
             {"artifact_id", "artifact.cb"}, {"row_pitch", sizeof(constants)}, {"depth_pitch", sizeof(constants)}}})}},
        {{"id", "res.gbuffer0"}, {"kind", "texture2d"}, {"descriptor", d11::Texture2DDescriptor(targetDesc)},
         {"content_policy", "undefined"}, {"initial_data", Json::array()}},
    });
    Json views = Json::array({{{"id", "view.gbuffer0.rtv"}, {"kind", "rtv"}, {"resource_id", "res.gbuffer0"},
                              {"descriptor", d11::RenderTargetViewDescriptor(rtvDesc)}}});
    Json shaders = Json::array({
        {{"id", "shader.vs"}, {"stage", "vs"}, {"artifact_id", "artifact.vs"}, {"bytecode_sha256", vsHash},
         {"class_linkage_id", nullptr}, {"required_bindings", d11::ReflectRequirements(vsBytes->GetBufferPointer(), vsBytes->GetBufferSize())}},
        {{"id", "shader.ps"}, {"stage", "ps"}, {"artifact_id", "artifact.ps"}, {"bytecode_sha256", psHash},
         {"class_linkage_id", nullptr}, {"required_bindings", d11::ReflectRequirements(psBytes->GetBufferPointer(), psBytes->GetBufferSize())}},
    });
    Json layouts = Json::array({{{"id", "layout.body"}, {"signature_artifact_id", "artifact.vs"},
        {"shader_signature_sha256", vsHash}, {"elements", Json::array({
            {{"semantic_name", "POSITION"}, {"semantic_index", 0}, {"format", d11::DxgiFormat(DXGI_FORMAT_R32G32_FLOAT)},
             {"input_slot", 0}, {"aligned_byte_offset", 0}, {"input_slot_class", "per_vertex"},
             {"instance_data_step_rate", 0}}
        })}}});
    Json states = Json::array({{{"id", "state.rasterizer"}, {"kind", "rasterizer"},
                               {"descriptor", d11::RasterizerDescriptor(rasterizerDesc)}}});

    Json events = Json::array({
        {{"id", 0}, {"op", "create_object"}, {"object_id", "res.vb"}, {"call", "CreateBuffer"}},
        {{"id", 1}, {"op", "create_object"}, {"object_id", "res.cb"}, {"call", "CreateBuffer"}},
        {{"id", 2}, {"op", "create_object"}, {"object_id", "res.gbuffer0"}, {"call", "CreateTexture2D"}},
        {{"id", 3}, {"op", "create_object"}, {"object_id", "view.gbuffer0.rtv"}, {"call", "CreateRenderTargetView"}},
        {{"id", 4}, {"op", "create_object"}, {"object_id", "shader.vs"}, {"call", "CreateVertexShader"}},
        {{"id", 5}, {"op", "create_object"}, {"object_id", "shader.ps"}, {"call", "CreatePixelShader"}},
        {{"id", 6}, {"op", "create_object"}, {"object_id", "layout.body"}, {"call", "CreateInputLayout"}},
        {{"id", 7}, {"op", "create_object"}, {"object_id", "state.rasterizer"}, {"call", "CreateRasterizerState"}},
        {{"id", 8}, {"op", "set_state"}, {"call", "IASetInputLayout"}, {"arguments", Json::object()}, {"object_ids", Json::array({"layout.body"})}},
        {{"id", 9}, {"op", "set_state"}, {"call", "IASetVertexBuffers"}, {"arguments", {{"start_slot", 0}, {"strides", Json::array({stride})}, {"offsets", Json::array({offset})}}}, {"object_ids", Json::array({"res.vb"})}},
        {{"id", 10}, {"op", "set_state"}, {"call", "IASetPrimitiveTopology"}, {"arguments", {{"topology", "D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST"}}}, {"object_ids", Json::array()}},
        {{"id", 11}, {"op", "set_state"}, {"call", "VSSetShader"}, {"arguments", {{"class_instance_count", 0}}}, {"object_ids", Json::array({"shader.vs"})}},
        {{"id", 12}, {"op", "set_state"}, {"call", "VSSetConstantBuffers"}, {"arguments", {{"start_slot", 0}}}, {"object_ids", Json::array({"res.cb"})}},
        {{"id", 13}, {"op", "set_state"}, {"call", "PSSetShader"}, {"arguments", {{"class_instance_count", 0}}}, {"object_ids", Json::array({"shader.ps"})}},
        {{"id", 14}, {"op", "set_state"}, {"call", "RSSetState"}, {"arguments", Json::object()}, {"object_ids", Json::array({"state.rasterizer"})}},
        {{"id", 15}, {"op", "set_state"}, {"call", "RSSetViewports"}, {"arguments", {{"viewports", Json::array({{{"top_left_x", 0.0}, {"top_left_y", 0.0}, {"width", width}, {"height", height}, {"min_depth", 0.0}, {"max_depth", 1.0}}})}}}, {"object_ids", Json::array()}},
        {{"id", 16}, {"op", "set_state"}, {"call", "OMSetRenderTargets"}, {"arguments", {{"count", 1}}}, {"object_ids", Json::array({"view.gbuffer0.rtv"})}},
        {{"id", 17}, {"op", "clear_rtv"}, {"view_id", "view.gbuffer0.rtv"}, {"value", Json::array({0.0, 0.0, 0.0, 0.0})}},
        {{"id", 18}, {"op", "draw"}, {"call", "Draw"}, {"arguments", {{"vertex_count", 3}, {"start_vertex", 0}}}, {"snapshot_id", "snapshot.draw18"}},
    });
    Json bindingEvents = Json::array();
    for (unsigned id = 8; id <= 16; ++id) bindingEvents.push_back(id);
    Json snapshot = {
        {"id", "snapshot.draw18"}, {"event_id", 18}, {"binding_event_ids", bindingEvents},
        {"input_assembler", {{"input_layout_id", "layout.body"},
            {"primitive_topology", "D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST"},
            {"vertex_buffers", Json::array({{{"slot", 0}, {"resource_id", "res.vb"}, {"stride", stride}, {"offset", offset}}})},
            {"index_buffer", nullptr}}},
        {"stages", {{"vs", Stage("shader.vs", Json::array({Slot(0, "res.cb")}))}, {"ps", Stage("shader.ps")},
            {"gs", nullptr}, {"hs", nullptr}, {"ds", nullptr}, {"cs", nullptr}}},
        {"stream_output", {{"targets", Json::array()}}},
        {"rasterizer", {{"state_id", "state.rasterizer"},
            {"viewports", Json::array({{{"top_left_x", 0.0}, {"top_left_y", 0.0}, {"width", width}, {"height", height},
                {"min_depth", 0.0}, {"max_depth", 1.0}}})}, {"scissors", Json::array()}}},
        {"output_merger", {{"rtvs", Json::array({Slot(0, "view.gbuffer0.rtv")})}, {"dsv_id", nullptr},
            {"uavs", Json::array()}, {"blend_state_id", nullptr}, {"blend_factor", Json::array({1.0, 1.0, 1.0, 1.0})},
            {"sample_mask", UINT32_MAX}, {"depth_stencil_state_id", nullptr}, {"stencil_ref", 0}}},
        {"predication", {{"predicate_id", nullptr}, {"value", false}}},
    };

    Json manifest = {
        {"schema", "uc.d3d11-capture.v1"}, {"capture_id", "owned-d3d11-body-draw"}, {"api", "d3d11"},
        {"capture_kind", "golden_replay"}, {"validation_mode", "golden"},
        {"source", {{"capturer", "UnifiedCapture owned D3D11 fixture"}, {"capturer_version", "1"},
            {"captured_utc", uc::WallClockUtc()},
            {"executable", {{"name", "D3D11CaptureFixture.exe"}, {"sha256", uc::FileSha(executablePath)}}},
            {"modules", Json::array()},
            {"adapter", {{"vendor_id", adapterDesc.VendorId}, {"device_id", adapterDesc.DeviceId},
                         {"luid", d11::AdapterLuid(adapterDesc.AdapterLuid)}}},
            {"feature_level", d11::FeatureLevel(level)}}},
        {"frame", {{"frame_index", 0}, {"width", width}, {"height", height}}},
        {"completeness", {{"object_creation", "complete"}, {"resource_initial_data", "complete"},
            {"resource_updates", "complete"}, {"binding_calls", "complete"}, {"event_order", "complete"},
            {"draw_snapshots", "complete"}, {"lossless_artifacts", true}}},
        {"objects", {{"resources", resources}, {"views", views}, {"shaders", shaders},
            {"input_layouts", layouts}, {"states", states}, {"class_linkages", Json::array()},
            {"class_instances", Json::array()}, {"asynchronous", Json::array()},
            {"pipeline_snapshots", Json::array({snapshot})}}},
        {"events", events}, {"entry_event_id", 0}, {"target_draw_event_ids", Json::array({18})},
        {"checkpoints", Json::array({{{"id", "checkpoint.after-draw18"}, {"phase", "after_event"}, {"event_id", 18},
            {"attachments", Json::array({{{"resource_id", "res.gbuffer0"}, {"subresource", 0},
                {"view_id", "view.gbuffer0.rtv"}, {"aspect", "color"}, {"artifact_id", "artifact.reference"},
                {"row_pitch", width * 4}, {"depth_pitch", width * height * 4},
                {"comparison", {{"mode", "exact_unorm"}}}}})}}})},
    };
    writer.Seal(std::move(manifest));
    std::wcout << L"capture=" << (writer.Root() / L"capture.json").c_str() << L"\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << "\n";
    return 2;
}
