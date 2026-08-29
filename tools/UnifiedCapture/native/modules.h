#pragma once
#include "common.h"
namespace uc {
void InitializeModuleNotifications();
std::pair<uint32_t,uint64_t> ObserveModule(uint64_t base);
bool ModuleStillLoaded(const Module&) noexcept;
// Process-wide counter bumped on every module load/unload notification.
// Callbacks compare a cached value for O(1) liveness instead of walking the
// module list on every event.
uint64_t ModuleEpochSerial() noexcept;
Json ModuleNotificationStatus();
}
