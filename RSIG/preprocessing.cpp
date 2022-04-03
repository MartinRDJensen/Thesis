#include "RSIG/CurveElement.h"
#include "RSIG/RSIGOptions.h"
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
void preprocessing(RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size){
  std::cout << "IN PREPROCESSING" << std::endl;
  bool prep_mul = opts.prep_mul;
  std::cout << prep_mul << std::endl;
  Timer timer;
  timer.start();
  Player& P = proc.P;
  auto& prep = proc.DataF;
  //size_t start = P.total_comm().sent;
  //auto stats = P.total_comm();
  auto& extra_player = P;

 // auto& protocol = proc.protocol;
  auto& MCp = proc.MC;

  typedef T<typename CurveElement::Scalar> scalarShare;
  typedef T<CurveElement> pointShare;
  CurveElement hP;
  CurveElement G(1);
  //outer vector index is party index
  //Inner vector index is PKSET index
  std::vector<std::vector<pointShare>> L;
  std::vector<std::vector<pointShare>> R;
  prep.buffer_triples();
  vector<scalarShare> test;
  scalarShare testt;
  prep.get_one(DATA_BIT, testt);
  test.push_back(testt);
  cout << "test is: " << testt << endl;
  vector<CurveElement::Scalar> haha;
  MCp.POpen_Begin(haha, test, extra_player);
  MCp.POpen_End(haha, test, extra_player);
  std::cout << "opened: " << haha.at(0) << std::endl;

  prep.buffer_triples();
  std::vector<scalarShare> qs, ws;
  for(int i = 0; i < 6; i++){
    scalarShare q, w, _tmp;
    prep.get_three(DATA_TRIPLE, q, w, _tmp);
    qs.push_back(q);
    ws.push_back(w);
  }

  auto res = qs.at(0);
  cout << res * G << endl;
  std::cout << res << std::endl;
  std::cout << buffer_size << std::endl;
  //std::vector<std::vector<scalarShare>> qs, ws, c;
  //buffer size should be number of Pks
 /* for(int i = 0; i < buffer_size; i++){
    std::cout << "i = " << i << std::endl;
    std::vector<scalarShare> tmp_qs;
    std::vector<scalarShare> tmp_ws;
    for(int j = 0; j < 6; j ++){
      std::cout << "j = " << j << std::endl;
      scalarShare q, w, _tmp;
      prep.get_three(DATA_TRIPLE, q, w, _tmp);
      std::cout << "j = " << j << std::endl;
      std::cout << "j = " << j << std::endl;
      tmp_qs.push_back(q);
      tmp_ws.push_back(w);
    }
    qs.push_back(tmp_qs);
    ws.push_back(tmp_ws);
  }*/

  //std::cout << G << std::endl;
  //std::cout << G.operator*(res) << std::endl;

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
