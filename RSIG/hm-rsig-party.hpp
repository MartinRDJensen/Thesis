#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Protocols/Replicated.h"
#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/ReplicatedInput.h"
#include "Math/gfp.h"


#include "RSIG/CurveElement.h"
#include "RSIG/preprocessing.hpp"
#include "RSIG/sign.hpp"


#include "Tools/Bundle.h"
#include "GC/TinyMC.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/CcdSecret.h"
#include "GC/VectorInput.h"
#include "Protocols/MaliciousRepMC.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Processor/Input.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"
#include "GC/Secret.hpp"
#include "Machines/ShamirMachine.hpp"

#include <assert.h>

template<template<class U> class T>
void run(int argc, const char** argv)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    RSIGOptions opts(opt, argc, argv);
    Names N(opt, argc, argv, 3);
    int buffer_size = 1000;
    if (not opt.lastArgs.empty())
        buffer_size = atoi(opt.lastArgs[0]->c_str());
    CryptoPlayer P(N, "rsig");
    CurveElement::init();
    typedef T<CurveElement::Scalar> pShare;
    OnlineOptions::singleton.batch_size = 1;
    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    pShare sk = typename T<CurveElement::Scalar>::Honest::Protocol(P).get_random();
    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * buffer_size;
    DataPositions usage;
    typename pShare::TriplePrep prep(0, usage);
    typename pShare::MAC_Check MCp;
    ArithmeticProcessor _({}, 0);
    SubProcessor<pShare> proc(_, MCp, prep, P);

    bench_coll timer_struct;
    vector<RSIGTuple<T>> tuples(buffer_size);
    // BEGIN FOR HIDING THE RECEIVER
    //THEY DO HAVE THE SIGNER SECRET KEY IN test_keys WHICH IS NOT GOOD
    vector<pShare> skk;
    skk.push_back(sk);
    vector<CurveElement::Scalar> sk_open;

    MCp.POpen_Begin(sk_open, skk , P);
    MCp.POpen_End(sk_open, skk , P);
    MCp.Check(P);
    cout << "sk is " << sk_open.at(0) << endl;
    //auto test_keys = gen(sk.get_share());

    auto test_keys = gen(sk_open.at(0));
    SignatureTransaction *tx = genTransaction(get<2>(test_keys));
    auto publicKeys = genPublicKeys(5, get<1>(test_keys));
    cout << "Running protocol " << buffer_size << " times" << endl;
    pShare s = pShare::constant(0, proc.P.my_num(), MCp.get_alphai());

    preprocessing_subscript(tuples, opts, proc, buffer_size, publicKeys, get<2>(test_keys), s, &timer_struct, 0);
    sign_benchmark(tx, tuples, sk, get<2>(test_keys), publicKeys, MCp, P, proc, &timer_struct);
    print_timers(&timer_struct, buffer_size);
}
