#include "CurveElement.h"
#include "RSIGOptions.h"
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
  T<CurveElement::Scalar> secret_R;
  T<CurveElement::Scalar> secret_challenges;
  T<CurveElement::Scalar> secret_responses;
};

/*template<template<class U> class T>
void preprocessing(vector<RSIGTuple<T>>& tuples, int buffer_size,
        T<CurveElement::Scalar>& sk,
        SubProcessor<T<CurveElement::Scalar>>& proc,
        RSIGOptions opts){
*/
template<template<class U> class T>
void preprocessing(RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size){
  bool prep_mul = opts.prep_mul;
  std::cout << prep_mul << std::endl;
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
  CurveElement hP;
  //outer vector index is party index
  //Inner vector index is PKSET index
  std::vector<std::vector<pointShare>> L;
  std::vector<std::vector<pointShare>> R;
  prep.buffer_triples();
  std::vector<std::vector<scalarShare>> qs, ws, c;
  //buffer size should be number of Pks
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < 6; j ++){
      scalarShare q, w, _tmp;
      prep.get_three(DATA_TRIPLE, q, w, _tmp);
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
