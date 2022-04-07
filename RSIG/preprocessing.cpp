#include "RSIG/CurveElement.h"
#include "RSIG/RSIGOptions.h"
#include "RSIG/util.h"
#include "RSIG/transaction.h"



#include "Processor/Data_Files.h"
#include "Protocols/ReplicatedPrep.h"
#include "Protocols/MaliciousShamirShare.h"
#include "Protocols/Rep3Share.h"
#include "GC/TinierSecret.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/TinyMC.h"
#include "GC/TinierSharePrep.hpp"
#include "GC/CcdSecret.h"
//#include "eq.cpp"
#include <typeinfo>

template<template<class U> class T>
class RSIGTuple{
public:
  vector<T<CurveElement>> secret_L;
  T<CurveElement::Scalar> eq_bit_shares;
  vector<T<CurveElement>> secret_R;
};

/*template<template<class U> class T>
void preprocessing(vector<RSIGTuple<T>>& tuples, int buffer_size,
        T<CurveElement::Scalar>& sk,
        SubProcessor<T<CurveElement::Scalar>>& proc,
        RSIGOptions opts){
*/
template<template<class U> class T>
void preprocessing(SignatureTransaction* message, vector<RSIGTuple<T>>& tuples, RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I){
  std::cout << "IN PREPROCESSING" << std::endl;
  bool prep_mul = opts.prep_mul;
  std::cout << prep_mul << std::endl;
  std::cout << message << std::endl;
  Timer timer;
  timer.start();
  Player& P = proc.P;
  auto& prep = proc.DataF;
  //size_t start = P.total_comm().sent;
  //auto stats = P.total_comm();
  auto& extra_player = P;

  auto& protocol = proc.protocol;
  auto& MCp = proc.MC;
  typedef T<typename CurveElement::Scalar> scalarShare;
  typedef T<CurveElement> pointShare;
  //typename pointShare::Direct_MC MCc(MCp.get_alphai());
  CurveElement G(1);
  std::vector<std::vector<pointShare>> L;
  std::vector<std::vector<pointShare>> R;
  prep.buffer_triples();
  vector<vector<scalarShare>> bitShares(buffer_size);
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){
      scalarShare bitShare;
      prep.get_one(DATA_BIT, bitShare);
      bitShares.at(i).push_back(bitShare);
    }
  }
  vector<vector<scalarShare>> qs(buffer_size), ws(buffer_size);
  vector<vector<scalarShare>> w_mul_const_sub_b(buffer_size);
//  vector<vector<scalarShare>> wBs;
  auto shareOfOne =  scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
  for(int j = 0; j < buffer_size; j++){
    for(int i = 0; i < 6; i++){
      scalarShare q, w, _tmp;
      prep.get_three(DATA_TRIPLE, q, w, _tmp);
      /*auto qShares = q.get_share();
      //auto qMACs = q.get_mac();
      auto qG = G.operator*(qShares);
      pointShare qGShare;
      qGShare.set_share(qG);
      qGShare.set_mac(q.get_mac());//gang med mac?*/
      qs.at(j).push_back(q);
      ws.at(j).push_back(w);
    }
  }
  protocol.init_mul();
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){
      protocol.prepare_mul(ws.at(i).at(j), shareOfOne - bitShares.at(i).at(j));
    }
  }
  protocol.start_exchange();
  protocol.stop_exchange();
  MCp.Check(extra_player);
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j ++){
      auto tmp = protocol.finalize_mul();
      w_mul_const_sub_b.at(i).push_back(tmp);
    }
  }
   //l = [q]G+[w](1-[b])P
  //r = [q]hP + [w](1-[b])I
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){
      auto qVal = qs.at(i).at(j).get_share();
      auto qMAC = qs.at(i).at(j).get_mac();
      auto qG = G.operator*(qVal);
      pointShare qGShare;
      qGShare.set_share(qG);
      qGShare.set_mac(qMAC);
      auto tmp = w_mul_const_sub_b.at(i).at(j);
      auto wconstShare = tmp.get_share();
      auto wconstMAC = tmp.get_mac();
      auto wConstP = publicKeys.at(j).operator*(wconstShare);
      pointShare stuffP;
      stuffP.set_share(wConstP);
      stuffP.set_mac(wconstMAC);
      auto roll = qGShare + stuffP;
      cout << " ffge " << roll << endl;
      tuples.at(i).secret_L.push_back(roll);

      cout << " fdsdfge " << roll << endl;
      unsigned char h[crypto_hash_sha512_BYTES];
      CurveElement::get_hash(h, publicKeys.at(j));
      CurveElement hP = CurveElement::hash_to_group(h);

      auto qhP = hP.operator*(qVal);
      pointShare qhPShare;
      qhPShare.set_share(qhP);
      qhPShare.set_mac(qMAC);
      auto wConstI = I.operator*(wconstShare);
      pointShare stuffI;
      stuffI.set_share(wConstI);
      stuffI.set_mac(wconstMAC);
      roll = qhPShare + stuffI;
      tuples.at(i).secret_R.push_back(roll);


    }
  }

   for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){

    }
  }

 for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){

    }
  }










}

