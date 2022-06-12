#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "CurveElement.h"
#include "Protocols/SemiShare.h"
#include "Processor/BaseMachine.h"

#include "RSIG/preprocessing.hpp"
#include "RSIG/sign.hpp"
#include "Protocols/ProtocolSet.h"

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
    int buffer_size = 1000;
    if (not opt.lastArgs.empty())
        buffer_size = atoi(opt.lastArgs[0]->c_str());
    PlainPlayer P(N, "rsig");
    CurveElement::init();
    CurveElement::Scalar::next::init_field(CurveElement::Scalar::pr(), false);

    BaseMachine machine;
    machine.ot_setups.push_back({P, true});

    // BaseMachine machinea;
    // machinea.ot_setups.push_back({P, true});

    // int offset = rand() % 100 + 1;
    // machine.thread_num = (P.my_num() + 1) * (offset + 1);
    // machinea.thread_num = (P.my_num() + 1) * (offset);
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

    // int ged; --- Data_Files.h
    // pShare idnex;
    // sk_prep.get_secret_index(DATA_INVERSE, idnex);
    // cout << idnex;
    // cin >> ged;
    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * (buffer_size );//+ 100);
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
    cout << prep_mul << endl;
    prep.params.use_extension = not opt.isSet("-S");

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
    preprocessing(tuples, opts, proc, buffer_size, publicKeys, get<2>(test_keys), s, &timer_struct, 0);
    sign_benchmark(tx, tuples, sk, get<2>(test_keys), publicKeys, MCp, P, proc, &timer_struct);
     print_timers(&timer_struct, buffer_size);
}
