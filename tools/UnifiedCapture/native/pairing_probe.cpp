#include "pairing.h"
#include <iostream>

int main(){
    using namespace uc;bool ok=true;std::array<PairFrame,8> out{};
    auto require=[&](bool value){ok&=value;};
    const std::array<uint32_t,2> exits{7,8};

    PairLedger shared(8);
    require(shared.Open(1,17,100,1001,0x1000,exits)==PairOpenResult::Opened);
    require(shared.Open(2,17,100,1002,0x1000,exits)==PairOpenResult::Opened);
    auto n=shared.Close(7,out);require(n==2&&shared.Size()==0&&out[0].generation==17&&out[1].generation==17);

    PairLedger recursive(8);
    require(recursive.Open(1,17,101,2001,0x1000,exits)==PairOpenResult::Opened);
    require(recursive.Open(1,18,102,2002,0x0f00,exits)==PairOpenResult::Opened);
    n=recursive.Close(7,out);require(n==1&&out[0].callGroup==102&&out[0].generation==18&&recursive.Size()==1);
    n=recursive.Close(7,out);require(n==1&&out[0].callGroup==101&&out[0].generation==17&&recursive.Size()==0);

    PairLedger sharedExit(8);
    require(sharedExit.Open(11,17,201,3001,0x1000,exits)==PairOpenResult::Opened);
    require(sharedExit.Open(22,17,202,3002,0x0f00,exits)==PairOpenResult::Opened);
    n=sharedExit.Close(7,out);require(n==1&&out[0].logicalObservation==22&&sharedExit.Size()==1);

    PairLedger absent(8);
    require(absent.Open(1,17,301,4001,0x1000,exits)==PairOpenResult::Opened);
    n=absent.PruneAbsent(0x1000,out);require(n==1&&out[0].invocation==4001&&absent.Size()==0);

    PairLedger bounded(1);
    require(bounded.Open(1,17,401,5001,0x1000,exits)==PairOpenResult::Opened);
    require(bounded.Open(2,17,402,5002,0x0f00,exits)==PairOpenResult::CapacityExhausted);
    const std::array<uint32_t,0> none{};
    require(PairLedger(1).Open(1,17,1,1,0x1000,none)==PairOpenResult::Invalid);

    std::cout<<"{\"schema\":\"uc.pair-ledger-fixture.v1\",\"ok\":"<<(ok?"true":"false")
             <<",\"shared_logical_subscriptions\":2,\"recursive_generations_preserved\":true"
             <<",\"shared_epilogue_closes_latest_group_only\":true"
             <<",\"absence_semantics\":\"frame_absent_after_observed_point\"}"<<std::endl;
    return ok?0:1;
}
