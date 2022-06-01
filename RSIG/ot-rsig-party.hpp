#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "CurveElement.h"
#include "Protocols/SemiShare.h"
#include "Processor/BaseMachine.h"

#include "RSIG/preprocessing.cpp"
#include "RSIG/sign.cpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MascotPrep.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Input.hpp"
#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"

#include <assert.h>

template<template<class U> class T>
void run(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    RSIGOptions opts(opt, argc, argv);
    opt.add(
            "", // Default.
           0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use SimpleOT instead of OT extension", // Help description.
            "-S", // Flag token.
            "--simple-ot" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Don't check correlation in OT extension (only relevant with MASCOT)", // Help description.
            "-U", // Flag token.
            "--unchecked-correlation" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Fewer rounds for authentication (only relevant with MASCOT)", // Help description.
            "-A", // Flag token.
            "--auth-fewer-rounds" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use Fiat-Shamir for amplification (only relevant with MASCOT)", // Help description.
            "-H", // Flag token.
            "--fiat-shamir" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Skip sacrifice (only relevant with MASCOT)", // Help description.
            "-E", // Flag token.
            "--embrace-life" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "No MACs (only relevant with MASCOT; implies skipping MAC checks)", // Help description.
            "-M", // Flag token.
            "--no-macs" // Flag token.
    );

    Names N(opt, argc, argv, 2);
    int n_tuples = 10;
    if (not opt.lastArgs.empty())
        n_tuples = atoi(opt.lastArgs[0]->c_str());
    PlainPlayer P(N, "rsig");
    CurveElement::init();
    CurveElement::Scalar::next::init_field(CurveElement::Scalar::pr(), false);

    BaseMachine machine;
    machine.ot_setups.push_back({P, true});

    CurveElement::Scalar keyp;
    SeededPRNG G;
    keyp.randomize(G);

    typedef T<CurveElement::Scalar> pShare;
    DataPositions usage;

    OnlineOptions::singleton.batch_size = 1;
    typename pShare::Direct_MC MCp(keyp);
    ArithmeticProcessor _({}, 0);
    typename pShare::TriplePrep sk_prep(0, usage);
    SubProcessor<pShare> sk_proc(_, MCp, sk_prep, P);
    pShare sk, __;

    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    sk_prep.get_two(DATA_INVERSE, sk, __);
    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * n_tuples;
    typename pShare::TriplePrep prep(0, usage);
    prep.params.correlation_check &= not opt.isSet("-U");
    prep.params.generateBits = true;
    prep.params.fewer_rounds = opt.isSet("-A");
    prep.params.fiat_shamir = opt.isSet("-H");
    prep.params.check = not opt.isSet("-E");
    prep.params.generateMACs = not opt.isSet("-M");
    opts.check_beaver_open &= prep.params.generateMACs;
    opts.check_open &= prep.params.generateMACs;
    SubProcessor<pShare> proc(_, MCp, prep, P);
    typename pShare::prep_type::Direct_MC MCpp(keyp);
    prep.triple_generator->MC = &MCpp;

    bool prep_mul = not opt.isSet("-D");
    prep.params.use_extension = not opt.isSet("-S");

    // READ BITS AND SENDERS INDEX
    string prefix = get_prep_sub_dir<pShare>(PREP_DIR "RSIG/", 2);
    read_mac_key(prefix, N, keyp);
    Sub_Data_Files<pShare> prep2(N, prefix, usage);
    SubProcessor<pShare> proc2(_, MCp, prep2, P);
    pShare tmp, s;
    proc.DataF.get_two(DATA_INVERSE, tmp, s);

    bench_coll timer_struct;
    vector<RSIGTuple<Share>> tuples(n_tuples);
    // BEGIN FOR HIDING THE RECEIVER
    //THEY DO HAVE THE SIGNER SECRET KEY IN test_keys WHICH IS NOT GOOD
    cout << "KEY " << sk.get_share() << endl;
    //auto test_keys = gen(sk.get_share());

    auto test_keys = gen(5);
    SignatureTransaction *tx = genTransaction(get<2>(test_keys));
    auto publicKeys = genPublicKeys(5, get<1>(test_keys));
    cout << "Running protocol " << n_tuples << " times" << endl;
    preprocessing(tuples, opts, proc, n_tuples, publicKeys, get<2>(test_keys), s, &timer_struct);
    cout << "starign sign bench" << endl;
    cout << "starign sign bench" << endl;
    cout << "starign sign bench" << endl;
    cout << "starign sign bench" << endl;
    cout << "starign sign bench" << endl;
    sign_benchmark(tx, tuples, sk, get<2>(test_keys), publicKeys, MCp, P, proc, &timer_struct);
    cout << "after sign bench" << endl;
    cout << "after sign bench" << endl;
    cout << "after sign bench" << endl;
    cout << "after sign bench" << endl;
    cout << "after sign bench" << endl;
    cout << "after sign bench" << endl;
    cout << "after sign bench" << endl;
}
