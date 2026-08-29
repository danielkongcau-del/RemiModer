#pragma once
#include "plan.h"
namespace uc {
void ConfigureLegacy(Point&,const Json&,const std::unordered_map<std::string,Module>&);
void CaptureLegacy(Point&,Record&,const Abi&) noexcept;
Json LegacyCapabilities();
}
