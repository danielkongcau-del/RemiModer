#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace uc {

// Callback-safe bookkeeping only. It records observed nesting and normal-exit
// matches; it does not infer an exception when a frame later becomes absent.
struct PairFrame {
    uint64_t logicalObservation=0,generation=0,callGroup=0,invocation=0,entryRsp=0;
    std::array<uint32_t,8> exitHooks{};
    uint32_t exitHookCount=0;
};

enum class PairOpenResult { Opened, CapacityExhausted, TooManyExitHooks, Invalid };

class PairLedger {
    std::unique_ptr<PairFrame[]> frames;
    size_t capacity=0,count=0;
    bool Matches(const PairFrame& frame,uint32_t hook)const noexcept {
        for(uint32_t i=0;i<frame.exitHookCount;++i)if(frame.exitHooks[i]==hook)return true;
        return false;
    }
    template<class Predicate>
    size_t Extract(Predicate predicate,std::span<PairFrame> output)noexcept {
        size_t needed=0;for(size_t i=0;i<count;++i)if(predicate(frames[i]))++needed;
        // If the caller cannot account for every extracted frame, leave the
        // ledger untouched: silent truncation would fabricate clean pairing.
        if(needed>output.size())return SIZE_MAX;
        size_t written=0,kept=0;
        for(size_t i=0;i<count;++i){
            if(predicate(frames[i])){
                if(written<output.size())output[written]=frames[i];
                ++written;
            }else {if(kept!=i)frames[kept]=frames[i];++kept;}
        }
        count=kept;return written;
    }
public:
    explicit PairLedger(size_t maximum):frames(maximum?std::make_unique<PairFrame[]>(maximum):nullptr),capacity(maximum){}
    PairOpenResult Open(uint64_t logical,uint64_t generation,uint64_t group,uint64_t invocation,
                        uint64_t rsp,std::span<const uint32_t> exits)noexcept {
        if(!logical||!generation||!group||!invocation||!rsp||exits.empty())return PairOpenResult::Invalid;
        if(exits.size()>PairFrame{}.exitHooks.size())return PairOpenResult::TooManyExitHooks;
        if(count==capacity)return PairOpenResult::CapacityExhausted;
        PairFrame frame;frame.logicalObservation=logical;frame.generation=generation;frame.callGroup=group;
        frame.invocation=invocation;frame.entryRsp=rsp;frame.exitHookCount=(uint32_t)exits.size();
        for(size_t i=0;i<exits.size();++i)frame.exitHooks[i]=exits[i];
        frames[count++]=frame;return PairOpenResult::Opened;
    }
    // A shared epilogue closes only the most recently entered matching call
    // group, then all logical subscriptions opened by that same physical hit.
    size_t Close(uint32_t hook,std::span<PairFrame> output)noexcept {
        uint64_t group=0;for(size_t i=count;i>0;--i)if(Matches(frames[i-1],hook)){group=frames[i-1].callGroup;break;}
        if(!group)return 0;
        return Extract([&](const PairFrame& frame){return frame.callGroup==group&&Matches(frame,hook);},output);
    }
    // Called only after normal-exit matching at an actually observed point.
    // These rows mean frame_absent_after_observed_point, never exception_exit.
    size_t PruneAbsent(uint64_t observedRsp,std::span<PairFrame> output)noexcept {
        if(!observedRsp)return 0;
        return Extract([&](const PairFrame& frame){return observedRsp>=frame.entryRsp;},output);
    }
    uint64_t ObservedParent(uint64_t rsp)const noexcept {
        if(!rsp)return 0;
        for(size_t i=count;i>0;--i)if(frames[i-1].entryRsp>rsp)return frames[i-1].invocation;
        return 0;
    }
    size_t Size()const noexcept{return count;}
};

}
