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
  T<CurveElement::Scalar> secret_L;
  T<CurveElement::Scalar> eq_bit_shares;
  T<CurveElement::Scalar> secret_R;
};

/*template<template<class U> class T>
void preprocessing(vector<RSIGTuple<T>>& tuples, int buffer_size,
        T<CurveElement::Scalar>& sk,
        SubProcessor<T<CurveElement::Scalar>>& proc,
        RSIGOptions opts){
*/
template<template<class U> class T>
void preprocessing(SignatureTransaction* message, RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys){
  std::cout << "IN PREPROCESSING" << std::endl;
  bool prep_mul = opts.prep_mul;
  std::cout << prep_mul << std::endl;
  std::cout << message << std::endl;
  Timer timer;
  timer.start();
  //Player& P = proc.P;
  auto& prep = proc.DataF;
  //size_t start = P.total_comm().sent;
  //auto stats = P.total_comm();
  //auto& extra_player = P;

 // auto& protocol = proc.protocol;
  //auto& MCp = proc.MC;

  typedef T<typename CurveElement::Scalar> scalarShare;
  typedef T<CurveElement> pointShare;
  CurveElement G(1);
  //auto& MCp = proc.MC;
  std::vector<std::vector<pointShare>> L;
  std::vector<std::vector<pointShare>> R;
  prep.buffer_triples();
  vector<vector<scalarShare>> bitShares(1000);
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){
      scalarShare bitShare;
      prep.get_one(DATA_BIT, bitShare);
      bitShares.at(i).push_back(bitShare);
      cout << "I AM LOADING SHARES: " << bitShare << endl;
    }
  }
  vector<vector<scalarShare>> qs(buffer_size), ws(buffer_size);

  auto pksss = publicKeys.at(0);
  unsigned char h[crypto_hash_sha512_BYTES];
  CurveElement::get_hash(h, pksss);
  CurveElement hP = CurveElement::hash_to_group(h);
  cout << hP;
  //l = [q]G+[w](1-[b])P
  //r = [q]hP + [w](1-[b])I
//  vector<vector<scalarShare>> wBs;
  for(int j = 0; j < buffer_size; j++){
    cout << "NEW J: " << j << endl;
    //auto shareOfOne =  scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
    for(int i = 0; i < 6; i++){
      scalarShare q, w, _tmp;
      prep.get_three(DATA_TRIPLE, q, w, _tmp);
      auto qShares = q.get_share();
      //auto qMACs = q.get_mac();
      auto qG = G.operator*(qShares);

      //gang med mac?

      cout << qG;
      qs.at(j).push_back(q);
      ws.at(j).push_back(w);
    }
  }













}


/*
  std::vector<std::vector<CurveElement::Scalar>> eq_box;
  for(int k = 0; k < 2; k++){
    std::vector<CurveElement::Scalar> tmp;
    for(int j = 0; j < 6; j++){
      auto shared_bit = eq_testing(k,j);
      tmp.push_back(shared_bit);
    }
    eq_box.push_back(tmp);
  }
}
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j++){
      qs.at(i) - eq_box.at(0).at(j)
    }
  }
}
a,b,c is mult triple ; not sure if shares
secret R =>?
R => ?
R => probably kG
      T<CurveElement::Scalar> a;
    T<CurveElement::Scalar> b;
    CurveElement::Scalar c;
    T<CurveElement> secret_R;
    CurveElement R;
};
*/
