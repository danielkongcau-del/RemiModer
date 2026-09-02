#pragma once

#include "common.h"
#pragma warning(push)
#pragma warning(disable:4324)
#include "frida-gum.h"
#pragma warning(pop)
#include <memory>

namespace uc::d3d11 {

// Startup-resident D3D11 observer. It records the two pieces of pipeline
// identity that D3D11 cannot query later (shader bytecode and input-layout
// elements), then takes an authoritative context/resource snapshot only when
// an armed draw matches the configured bytecode identity.
class Observer {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    Observer(GumInterceptor* interceptor, fs::path observerDirectory, Json configuration);
    ~Observer();
    Observer(const Observer&) = delete;
    Observer& operator=(const Observer&) = delete;

    void Tick() noexcept;
    Json Status() const;
    Json Arm(const std::string& label);
    bool Ready() const noexcept;
    bool Captured() const noexcept;
};

}
