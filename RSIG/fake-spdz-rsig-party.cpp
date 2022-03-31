#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "CurveElement.h"
#include "GC/VectorInput.h"

#include "preprocessing.cpp"
//#include "sign.cpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "Processor/Input.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "Protocols/MascotPrep.hpp"
#include "GC/Secret.hpp"
#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"
#include "OT/NPartyTripleGenerator.hpp"
#include <assert.h>

int main(int argc, const char** argv){
    ez::ezOptionParser opt;
    RSIGOptions opts(opt, argc, argv);
    Names N(opt, argc, argv, 2);
    int n_tuples = 1000;
    if (not opt.lastArgs.empty())
        n_tuples = atoi(opt.lastArgs[0]->c_str());
    PlainPlayer P(N, "rsig");
    CurveElement::init();

    CurveElement::Scalar keyp;
    typedef Share<CurveElement::Scalar> pShare;
    string prefix = get_prep_sub_dir<pShare>(PREP_DIR "RSIG/", 2);
    read_mac_key(prefix, N, keyp);

    DataPositions usage;
    Sub_Data_Files<pShare> prep(N, prefix, usage);
    typename pShare::Direct_MC MCp(keyp);
    ArithmeticProcessor _({}, 0);
    BaseMachine machine;
    machine.ot_setups.push_back({P, false});
    SubProcessor<pShare> proc(_, MCp, prep, P);

    pShare sk, __;
    proc.DataF.get_two(DATA_INVERSE, sk, __);

    vector<RSIGTuple<Share>> tuples;
    preprocessing(opts, proc, n_tuples);
    //preprocessing(tuples, n_tuples, sk, proc, opts);
    //check(tuples, sk, keyp, P);
    //sign_benchmark(tuples, sk, MCp, P, opts);
}
