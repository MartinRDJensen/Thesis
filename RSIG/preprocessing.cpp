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
#include <bitset>

#include <math.h>

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
void preprocessing(vector<RSIGTuple<T>>& tuples, RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I, T<CurveElement::Scalar> s){
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
  typename pointShare::Direct_MC MCc(MCp.get_alphai());
  CurveElement G(1);
  std::vector<std::vector<pointShare>> L;
  std::vector<std::vector<pointShare>> R;
  prep.buffer_triples();
  vector<vector<vector<scalarShare>>> bitShares;
  vector<vector<scalarShare>> rrShares(buffer_size);
  int number_of_parties = 6;

  cout << "s is " << s << endl;
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j++){
      scalarShare _, r;
      prep.get_two(DATA_INVERSE, _, r);
      //cout << "r is " << r << endl;
      rrShares.at(i).push_back(r);
    }
  }

  for(int i = 0; i < buffer_size; i++) {
    vector<vector<scalarShare>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      vector<scalarShare> tmp1;
      for(int k = 0; k < 40 ; k++) {
        scalarShare bitShare;
        prep.get_one(DATA_BIT, bitShare);
        tmp1.push_back(bitShare);
      }
      tmp.push_back(tmp1);
    }
    bitShares.push_back(tmp);
  }


  vector<vector<scalarShare>> rShares(buffer_size);

  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      scalarShare r_prime;
      CurveElement::Scalar two = 1;
      for(int k = 0; k < 40; k++) {
          if( k != 0) {
            CurveElement::Scalar tmp = 2;
            two = two * tmp;
          }
          auto r = two * bitShares.at(i).at(j).at(k);
          r_prime = r_prime + r;
      }
      cout << "r_prime " << r_prime << endl;
      rShares.at(i).push_back(r_prime);
    }
  }

  vector<vector<scalarShare>> cShares(buffer_size);

 

  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      CurveElement::Scalar two = 1;
      for(int k = 0; k < 41; k++) {
         if( k != 0) {
            CurveElement::Scalar tmp = 2;
            two = two * tmp;
          }
      }
      CurveElement::Scalar two_;
      for(int k = 0; k < 40; k++) {
         if( k != 0) {
            CurveElement::Scalar tmp = 2;
            two_ = two_ * tmp;
          }
      }
      auto shareOfPos = scalarShare::constant(j, proc.P.my_num(), MCp.get_alphai());
      auto shareOfTwo_ = scalarShare::constant(two_, proc.P.my_num(), MCp.get_alphai());
      auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      cShares.at(i).push_back(c);
    }
  }

  vector<vector<CurveElement::Scalar>> c_opened(buffer_size);

  for(int i = 0; i < buffer_size; i++) {
    MCp.POpen_Begin(c_opened.at(i), cShares.at(i), extra_player);
    MCp.POpen_End(c_opened.at(i), cShares.at(i), extra_player);
  }



  vector<vector<vector<CurveElement::Scalar>>> c_bits;

  for(int i = 0; i < buffer_size; i++) {
    vector<vector<CurveElement::Scalar>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      bigint val(c_opened.at(i).at(j));
      cout << "val is " << val << " other is  " << c_opened.at(i).at(j) << endl;
      vector<CurveElement::Scalar> tmp1;
      for(int k = 0; k < 40 ; k++) {
        CurveElement::Scalar s;
        if(val % 2 == 0) {
          s = 0;
        } else {
          s = 1;
        }
        val = val / 2;
        tmp1.push_back(s);
      }
      //std::reverse(tmp1.begin(), tmp1.end());
      tmp.push_back(tmp1);
    }
    c_bits.push_back(tmp);
  }

  vector<vector<vector<scalarShare>>> d_bits = bitShares;

  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      for(int k = 0; k < 40; k++) {
        protocol.init_mul();
        CurveElement::Scalar two = 2;
        auto r = bitShares.at(i).at(j).at(k);
        /*
        protocol.prepare_mul(r, r);
        protocol.start_exchange();
        protocol.stop_exchange();
        auto d = r + r - two * protocol.finalize_mul();
        */
        
        auto c = scalarShare::constant(c_bits.at(i).at(j).at(k), proc.P.my_num(), MCp.get_alphai());
        auto d = c + r - two * (c_bits.at(i).at(j).at(k) * r);
        
        d_bits.at(i).at(j).at(k) = d;
      }
    }
  }

  vector<vector<scalarShare>> z(buffer_size);

  for(int i = 0; i < buffer_size; i++) {
    cout << i << endl;
    for(int j = 0; j < number_of_parties; j++) {
      scalarShare sum;
      /*
      auto shareOfOne =  scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
      for(int k = 0; k < 40; k++) {
        sum = sum + d_bits.at(i).at(j).at(k);
      }
      sum = sum + shareOfOne;
      vector<scalarShare> tmp;

      for(int k = 0; k < 40; k++) {
        if(k == 0) {
          tmp.push_back(shareOfOne);
        } else {
          protocol.prepare_mul(tmp.at(i - 1), shareOfOne);
          protocol.start_exchange();
          protocol.stop_exchange();
          tmp.push_back(protocol.finalize_mul);
        }
      }
*/
      
      auto r = d_bits.at(i).at(j).at(0);
      for(int k = 1; k < 40; k++) {
        protocol.init_mul();
        protocol.prepare_mul(d_bits.at(i).at(j).at(k),r);
        protocol.start_exchange();
        protocol.stop_exchange();
        auto d = d_bits.at(i).at(j).at(k) + r - protocol.finalize_mul();
        r = d;
      }
      
      auto one = scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
      tuples.at(i).eq_bit_shares.push_back(one - r);
      //z.at(i).push_back(r);
    }
  }

  for(int i = 0; i < buffer_size; i++) {
        vector<CurveElement::Scalar> d_opened;
        MCp.POpen_Begin(d_opened, tuples.at(i).eq_bit_shares, extra_player);
        MCp.POpen_End(d_opened, tuples.at(i).eq_bit_shares, extra_player);
      for(auto x : d_opened) {
        cout << "z is " << x << endl;
      }
  }

  /*
  bigint bbb(c_opened.at(0).at(0));
  std::cout << "  " <<  bbb % 2 << std::endl;
  std::cout << " " <<  (bbb / 2) % 2 << std::endl;
  */


  vector<vector<scalarShare>> qs(buffer_size), ws(buffer_size);
  vector<vector<scalarShare>> w_mul_const_sub_b(buffer_size);
  auto shareOfOne =  scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
  for(int j = 0; j < buffer_size; j++){
    for(int i = 0; i < number_of_parties; i++){
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
    for(int j = 0; j < number_of_parties; j++){
      protocol.prepare_mul(ws.at(i).at(j), shareOfOne - tuples.at(i).eq_bit_shares.at(j));
    }
  }
  protocol.start_exchange();
  protocol.stop_exchange();
  MCp.Check(extra_player);
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j ++){
      auto tmp = protocol.finalize_mul();
      w_mul_const_sub_b.at(i).push_back(tmp);
    }
    tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  }
   //l = [q]G+[w](1-[b])P
  //r = [q]hP + [w](1-[b])I
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j++){
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

