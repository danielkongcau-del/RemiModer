#include "readers.h"
namespace uc {
Json LegacyCapabilities(){return {{"available",false},{"reason","target-bound-readers-not-in-public-build"}};}
void ConfigureLegacy(Point&,const Json& item,const std::unordered_map<std::string,Module>&){
    Require(!item.contains("legacy_reader"),"target-bound legacy readers are not part of the public build");
}
void CaptureLegacy(Point&,Record& record,const Abi&) noexcept {
    record.legacyOffset=0;record.legacySize=0;record.legacyFailures=0;record.legacyTruncated=false;
}
}
