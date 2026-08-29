#pragma once
#include "common.h"
namespace uc {
void InitializeModuleNotifications();
std::pair<uint32_t,uint64_t> ObserveModule(uint64_t base);
bool ModuleStillLoaded(const Module&) noexcept;
Json ModuleNotificationStatus();
}
