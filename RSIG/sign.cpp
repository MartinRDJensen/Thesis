#include "CurveElement.h"
#include "Math/gfp.hpp"
#include "Tools/Bundle.h"
#include "RSIG/util.h"
#include <vector>
#include <typeinfo>
CurveElement generator(1);

class RingSignature {
public:
  CurveElement keyImage;
  std::vector<CurveElement::Scalar> challenges;
  std::vector<CurveElement::Scalar> responses;
};

/*template <template <class U> class T>
RingSignature
sign(const unsigned char *message, RSIGTuple<T> tuple,
     typename T<CurveElement::Scalar>::MAC_Check &MC,
     typename T<CurveElement>::MAC_Check &MCc, Player &P, RSIGOptions opts,
     CurveElement pk, T<CurveElement::Scalar> sk = {},
     SubProcessor<T<CurveElement::Scalar>> *proc = 0)*/
template<template<class U> class T>
void sign(SignatureTransaction* message,
        //size_t length,
        RSIGTuple<T> tuple,
        typename T<CurveElement::Scalar>::MAC_Check& MCp,
        typename T<CurveElement>::MAC_Check& MCc,
        Player& P,
        //RSIGOptions opts,
        //T<CurveElement::Scalar> sk = {},
        SubProcessor<T<CurveElement::Scalar>>& proc){

  typedef T<typename CurveElement::Scalar> scalarShare;
/*  typedef T<CurveElement> pointShare;
*/
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    auto& protocol = proc.protocol;
    RingSignature signature;


    vector<CurveElement> opened_L;
    vector<CurveElement> opened_R;
    MCc.POpen_Begin(opened_L, {tuple.secret_L}, P);
    MCc.POpen_End(opened_L, {tuple.secret_L}, P);
    cout << "Starting first checks" << endl;
    cout << "Starting first checks" << endl;
    cout << "end of first checks" << endl;
    MCc.POpen_Begin(opened_R, {tuple.secret_R}, P);
    MCc.POpen_End(opened_R, {tuple.secret_R}, P);
    cout << "Starting first checks" << endl;
    cout << "end of first checks" << endl;

    unsigned char* m = reinterpret_cast<unsigned char*>(message);
    CurveElement::Scalar c = crypto_hash(m, opened_L, opened_R);
    cout << "challenge is: " << c << endl;
    scalarShare sum;
    auto shareOfC = scalarShare::constant(c, P.my_num(), MCp.get_alphai());
    cout << "abe0" << endl;
    for(T<CurveElement::Scalar> w : tuple.w_values) {
      sum = sum + w;
      cout << "abe1" << endl;
    }
    cout << "sum is: " << sum << endl;
    protocol.init_mul();
    for(int i = 0; i < 6; i++){
      auto tmp = shareOfC - sum + tuple.w_values.at(i);
      protocol.prepare_mul(tuple.eq_bit_shares.at(i), tmp);
      protocol.start_exchange();
      protocol.stop_exchange();
      auto prod = protocol.finalize_mul();
      cout << prod << endl;
    }


}

template <template <class U> class T>
/* void sign_benchmark(std::vector<RSIGTuple<T>> &tuples,
                    T<CurveElement::Scalar> sk,
                    typename T<CurveElement::Scalar>::MAC_Check &MCp, Player &P,
                    RSIGOptions &opts,
                    SubProcessor<T<CurveElement::Scalar>> *proc = 0)*/
void sign_benchmark(SignatureTransaction * message,
                    vector<CurveElement> publicKeys,
                    vector<RSIGTuple<T>> &tuples,
                    T<CurveElement::Scalar> sk,
                    typename T<CurveElement::Scalar>::MAC_Check &MCp,
                    Player &P,
                    SubProcessor<T<CurveElement::Scalar>>& proc){
  typename T<CurveElement>::Direct_MC MCc(MCp.get_alphai());

  for(CurveElement e : publicKeys){ cout << e << endl;}
  cout << sk << endl;

  Bundle<octetStream> bundle(P);
  P.unchecked_broadcast(bundle);
  //Bundle<octetStream> bundle(P);
  //P.Broadcast_Receive(bundle, true); // Broadcast and receive data to/from all
                                     // players with eventual verification.
  Timer timer;
  timer.start();
  auto stats = P.total_comm();         // NamedCommStats ??
  (P.total_comm() - stats).print(true); //??????

  for (size_t i = 0; i < min(10lu, tuples.size()); i++){
    /*check(sign(message, 1 << i, tuples[i], MCp, MCc, P, opts, pk, sk, proc),
    message, 1 << i, pk); if (not opts.check_open) continue; */
    sign(message, tuples[i], MCp, MCc, P, proc);
    Timer timer;
    timer.start();
    auto& check_player = MCp.get_check_player(P);
    auto stats = check_player.total_comm();
    MCp.Check(P);
    MCc.Check(P);
    cout << "DID A CHECK" << endl;
    cout << "i: " << i << endl;
    auto diff = (check_player.total_comm() - stats);
    cout << "Online checking took " << timer.elapsed() * 1e3 << " ms and sending "
        << diff.sent << " bytes" << endl;
    diff.print();
  }
}
