#define NO_MIXED_CIRCUITS

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "RSIG/CurveElement.h"
#include "GC/VectorInput.h"

#include "RSIG/preprocessing.cpp"
#include "RSIG/sign.cpp"

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
    vector<CurveElement::Scalar> tmp(1);
    pShare sk, __;
    proc.DataF.get_two(DATA_INVERSE, sk, __);
    vector<RSIGTuple<Share>> tuples(n_tuples);

    // BEGIN FOR HIDING THE RECEIVER
  //THEY DO HAVE THE SIGNER SECRET KEY IN test_keys WHICH IS NOT GOOD
    auto test_keys = gen(100000);
    SignatureTransaction *tx = genTransaction(get<2>(test_keys));
    auto publicKeys = genPublicKeys(5, get<1>(test_keys));
    // END FOR HIDING THE RECEIVER
    preprocessing(tuples, opts, proc, n_tuples, publicKeys, get<2>(test_keys));
    //check(tuples, sk, keyp, P);

    sign_benchmark(tx, tuples, sk, get<2>(test_keys), publicKeys, MCp, P, proc);
    //preprocessing(tuples, n_tuples, sk, proc, opts);
    //check(tuples, sk, keyp, P);
    //sign_benchmark(tuples, sk, MCp, P, opts);
}
