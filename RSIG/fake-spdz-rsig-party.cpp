#define NO_MIXED_CIRCUITS

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "RSIG/CurveElement.h"
#include "GC/VectorInput.h"

#include "RSIG/preprocessing.cpp"
#include "RSIG/sign.cpp"
#include <chrono>

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
    //int n_tuples = 1000;
    int buffer_size = 1000;
    if (not opt.lastArgs.empty())
        buffer_size = atoi(opt.lastArgs[0]->c_str());
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
    pShare sk, s;
    proc.DataF.get_two(DATA_INVERSE, sk, s);

    auto testbit = prep.get_bit();
    cout << "testibit test:" << testbit << endl;
    int asdf = 0;
    cin >> asdf;
    bench_coll timer_struct;
    vector<RSIGTuple<Share>> tuples(buffer_size);

    // BEGIN FOR HIDING THE RECEIVER
    //THEY DO HAVE THE SIGNER SECRET KEY IN test_keys WHICH IS NOT GOOD
    auto test_keys = gen(100000);
    SignatureTransaction *tx = genTransaction(get<2>(test_keys));
    auto publicKeys = genPublicKeys(5, get<1>(test_keys));
    preprocessing(tuples, opts, proc, buffer_size, publicKeys, get<2>(test_keys), s, &timer_struct);
    sign_benchmark(tx, tuples, sk, get<2>(test_keys), publicKeys, MCp, P, proc, &timer_struct);
    cout << "done" << endl;
    cout << "PRANDM took: " << timer_struct.PRANDM << " miliseconds." << endl;
    cout << "PRANDM took: " << (float) timer_struct.PRANDM / (float) 1000 << " seconds." << endl;
    cout << "Rest of EQ took: " << timer_struct.EQ_TEST_ALL << " miliseconds." << endl;
    cout << "Rest of EQ took: " << (float) timer_struct.EQ_TEST_ALL / (float) 1000 << " seconds." << endl;
    cout << "Triple consuming EQ took: " << timer_struct.EQ_TEST_TRIPLE_CONSUME << " miliseconds." << endl;
    cout << "Triple consuming EQ took: " << (float) timer_struct.EQ_TEST_TRIPLE_CONSUME / (float) 1000 << " seconds." << endl;
    cout << "q,w,L,R generation took: " << timer_struct.q_w_L_R << " miliseconds." << endl;
    cout << "q,w,L,R generation took: " << (float) timer_struct.q_w_L_R / (float) 1000 << " seconds." << endl;
    cout << "Average sign took: " << (float) timer_struct.buffer_size_sign / (float) buffer_size<< " miliseconds." << endl;
    cout << "Average sign took: " << ((float) timer_struct.buffer_size_sign / (float) buffer_size) / (float) 1000 << " seconds." << endl;
    cout << "Average verf took: " << (float) timer_struct.buffer_size_verf / (float) buffer_size << " miliseconds." << endl;
    cout << "Average verf took: " << ((float) timer_struct.buffer_size_verf / (float) buffer_size) / (float) 1000 << " seconds." << endl;
}
