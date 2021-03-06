#define NO_MIXED_CIRCUITS

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "RSIG/CurveElement.h"
#include "GC/VectorInput.h"

#include "RSIG/preprocessing.hpp"
#include "RSIG/sign.hpp"
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
  // RSIGOptions opts(opt, argc, argv);
  Names N(opt, argc, argv, 2);
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
  ArithmeticProcessor _({}, 1);
  BaseMachine machine;
  machine.ot_setups.push_back({P, false});
  SubProcessor<pShare> proc(_, MCp, prep, P);
  vector<CurveElement::Scalar> tmp(1);
  pShare sk, s;
  proc.DataF.get_two(DATA_INVERSE, sk, s);

  bench_coll timer_struct;
  vector<RSIGTuple<Share>> tuples(buffer_size);

  CurveElement::Scalar skk = 100000;
  auto test_keys = gen(skk);
  SignatureTransaction *tx = genTransaction(get<2>(test_keys));
  auto publicKeys = genPublicKeys(5, get<1>(test_keys));
  preprocessing(tuples, proc, buffer_size, publicKeys, get<2>(test_keys), s, &timer_struct, 1);
  sign_benchmark(tx, tuples, sk, get<2>(test_keys), publicKeys, MCp, P, proc, &timer_struct);
  print_timers(&timer_struct, buffer_size);
}
