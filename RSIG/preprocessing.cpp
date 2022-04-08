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
  vector<T<CurveElement::Scalar>> eq_bit_shares;
  vector<T<CurveElement>> secret_R;
  vector<T<CurveElement::Scalar>> w_mul_const_sub_bit;
  vector<T<CurveElement::Scalar>> q_values;
  vector<T<CurveElement::Scalar>> w_values;
};

template<template<class U> class T>
void preprocessing(vector<RSIGTuple<T>>& tuples, RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I){
  
  bool prep_mul = opts.prep_mul;
  Timer timer;
  timer.start();
  Player& P = proc.P;
  auto& prep = proc.DataF;
  size_t start = P.total_comm().sent;
  auto stats = P.total_comm();
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
      tuples.at(i).eq_bit_shares.push_back(bitShare);
    }
  }
  vector<vector<scalarShare>> qs(buffer_size), ws(buffer_size);
  vector<vector<scalarShare>> w_mul_const_sub_b(buffer_size);
  auto shareOfOne =  scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
  for(int j = 0; j < buffer_size; j++){
    for(int i = 0; i < 6; i++){
      scalarShare q, w, _tmp;
      prep.get_three(DATA_TRIPLE, q, w, _tmp);
      qs.at(j).push_back(q);
      ws.at(j).push_back(w);
    }

    tuples.at(j).q_values = qs.at(j);
    tuples.at(j).w_values = ws.at(j);

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
    tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  }
   //l = [q]G+[w](1-[b])P
  //r = [q]hP + [w](1-[b])I
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){
      cout << "PK" << j <<": " << publicKeys.at(j) << endl;
      auto qVal = qs.at(i).at(j).get_share();
      auto qMAC = qs.at(i).at(j).get_mac();
      auto qG = G.operator*(qVal);
      pointShare qGShare;
      qGShare.set_share(qG);
      qGShare.set_mac(G.operator*(qMAC));
      auto tmp = w_mul_const_sub_b.at(i).at(j);
      auto wconstShare = tmp.get_share();
      auto wconstMAC = tmp.get_mac();
      auto wConstP = publicKeys.at(j).operator*(wconstShare);
      pointShare stuffP;
      stuffP.set_share(wConstP);
      stuffP.set_mac(G.operator*(wconstMAC));
      auto roll = qGShare + stuffP;


      tuples.at(i).secret_L.push_back(roll);

      unsigned char h[crypto_hash_sha512_BYTES];
      CurveElement::get_hash(h, publicKeys.at(j));
      CurveElement hP = CurveElement::hash_to_group(h);

      auto qhP = hP.operator*(qVal);
      pointShare qhPShare;
      qhPShare.set_share(qhP);
      qhPShare.set_mac(G.operator*(qMAC));
      auto wConstI = I.operator*(wconstShare);
      pointShare stuffI;
      stuffI.set_share(wConstI);
      stuffI.set_mac(G.operator*(wconstMAC));
      roll = qhPShare + stuffI;
      tuples.at(i).secret_R.push_back(roll);


    }
  }

  timer.stop();
    cout << "Generated " << buffer_size << " tuples in " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}

