#include "RSIG/CurveElement.h"
#include "RSIG/RSIGOptions.h"
#include "RSIG/transaction.h"
#include <thread>
#include <algorithm>
#include <random>

#include "Processor/Data_Files.h"
#include "Protocols/ReplicatedPrep.h"
#include "Protocols/MaliciousShamirShare.h"
#include "Protocols/Rep3Share.h"
#include "GC/TinierSecret.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/TinyMC.h"
#include "GC/TinierSharePrep.hpp"
#include "GC/CcdSecret.h"
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
void preprocessing(vector<RSIGTuple<T>>& tuples, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I, T<CurveElement::Scalar> s, bench_coll *timer_struct, int flag){
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
  vector<scalarShare> bitters(40);
  if (flag == 0){
    prep.buffer_bits();
    for(int i = 0; i < 40; i ++){
      scalarShare teso;
      prep.get_one(DATA_BIT, teso);
      bitters.at(i) = teso;
    }
  }

  vector<vector<vector<scalarShare>>> bitShares;
  vector<vector<scalarShare>> rrShares(buffer_size);
  int number_of_parties = 6;
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  chrono::steady_clock::time_point eq_start = std::chrono::steady_clock::now();

  if(flag == 0){
    auto rng = default_random_engine {};
    for(int i = 0; i < buffer_size; i++){
      for(int j = 0; j < number_of_parties; j++){
        scalarShare r_prime_prime;
        shuffle(std::begin(bitters), std::end(bitters), rng);
        for(int inner = 0; inner < 40; inner ++){
          scalarShare curr = bitters.at(inner);
          auto c = powerMod(2, inner, (bigint(1) << 40));
          r_prime_prime += curr * c;
        }
        rrShares.at(i).push_back(r_prime_prime);
      }
    }
  }
  else {
    for(int i = 0; i < buffer_size; i++){
      for(int j = 0; j < number_of_parties; j++){
        scalarShare _, r;
        prep.get_two(DATA_INVERSE, _, r);
        rrShares.at(i).push_back(r);
      }
    }
  }
  vector<vector<scalarShare>> rShares(buffer_size);
  for(int i = 0; i < buffer_size; i++) {
    vector<vector<scalarShare>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      vector<scalarShare> tmp1(40);
      for(int k = 0; k < 40 ; k++) {
        scalarShare bitShare;
        prep.get_one(DATA_BIT, bitShare);
        tmp1.at(k) = bitShare;
      }
      tmp.push_back(tmp1);
    }
    bitShares.push_back(tmp);
  }
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
      rShares.at(i).push_back(r_prime);
    }
  }
  chrono::steady_clock::time_point eq_end = std::chrono::steady_clock::now();
  auto PRANDM = std::chrono::duration_cast<std::chrono::milliseconds>(eq_end - eq_start).count();
  timer_struct->PRANDM = PRANDM;
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START

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
      auto shareOfPos = scalarShare::constant(j, proc.P.my_num(), MCp.get_alphai());
      auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      cShares.at(i).push_back(c);
    }
  }
  vector<vector<CurveElement::Scalar>> c_opened(buffer_size);

  for(int i = 0; i < buffer_size; i++) {
    MCp.POpen_Begin(c_opened.at(i), cShares.at(i), extra_player);
    MCp.POpen_End(c_opened.at(i), cShares.at(i), extra_player);
    MCp.Check(extra_player);
  }
  vector<vector<vector<CurveElement::Scalar>>> c_bits;

  for(int i = 0; i < buffer_size; i++) {
    vector<vector<CurveElement::Scalar>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      bigint val(c_opened.at(i).at(j));
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
      tmp.push_back(tmp1);
    }
    c_bits.push_back(tmp);
  }

  vector<vector<vector<scalarShare>>> d_bits = bitShares;

  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      for(int k = 0; k < 40; k++) {
        CurveElement::Scalar two = 2;
        auto r = bitShares.at(i).at(j).at(k);

        auto c = scalarShare::constant(c_bits.at(i).at(j).at(k), proc.P.my_num(), MCp.get_alphai());
        auto d = c + r - two * (c_bits.at(i).at(j).at(k) * r);

        d_bits.at(i).at(j).at(k) = d;
      }
    }
  }
  vector<vector<scalarShare>> z(buffer_size);
  auto onlineEQstart = std::chrono::steady_clock::now();
  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      auto r = d_bits.at(i).at(j).at(0);
      for(int k = 1; k < 40; k++) {
        protocol.init_mul();
        protocol.prepare_mul(d_bits.at(i).at(j).at(k),r);
        protocol.start_exchange();
        protocol.stop_exchange();
        protocol.check();
        auto d = d_bits.at(i).at(j).at(k) + r - protocol.finalize_mul();
        r = d;
      }
      auto one = scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
      tuples.at(i).eq_bit_shares.push_back(one - r);
    }
  }

  chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
  auto equality_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - eq_start).count();
  auto equality_online_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - onlineEQstart).count();
  timer_struct->EQ_TEST_ALL = equality_testing;
  timer_struct->EQ_TEST_TRIPLE_CONSUME = equality_online_testing;
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END

  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
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
  protocol.check();
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j ++){
      auto tmp = protocol.finalize_mul();
      w_mul_const_sub_b.at(i).push_back(tmp);
    }
    tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  }

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
      stuffP.set_mac(publicKeys.at(j).operator*(wconstMAC));
      auto roll = qGShare + stuffP;

      tuples.at(i).secret_L.push_back(roll);

      unsigned char h[crypto_hash_sha512_BYTES];
      CurveElement::get_hash(h, publicKeys.at(j));
      CurveElement hP = CurveElement::hash_to_group(h);

      auto qhP = hP.operator*(qVal);
      pointShare qhPShare;
      qhPShare.set_share(qhP);
      qhPShare.set_mac(hP.operator*(qMAC));
      auto wConstI = I.operator*(wconstShare);
      pointShare stuffI;
      stuffI.set_share(wConstI);
      stuffI.set_mac(I.operator*(wconstMAC));
      roll = qhPShare + stuffI;
      tuples.at(i).secret_R.push_back(roll);
    }
  }
  end = std::chrono::steady_clock::now();
  auto sign_preprocessing = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  timer_struct->q_w_L_R = sign_preprocessing;
  timer.stop();
    cout << "Generated " << buffer_size << " tuples in " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}

template<template<class U> class T>
void preprocessing_subscript(vector<RSIGTuple<T>>& tuples, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I, T<CurveElement::Scalar> s, bench_coll *timer_struct, int flag){
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
  vector<scalarShare> bitters(40);
  if (flag == 0){
    prep.buffer_bits();
    for(int i = 0; i < 40; i ++){
      scalarShare teso;
      prep.get_one(DATA_BIT, teso);
      bitters.at(i) = teso;
    }
  }

  vector<vector<vector<scalarShare>>> bitShares;
  vector<vector<scalarShare>> rrShares(buffer_size);
  int number_of_parties = 6;
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  chrono::steady_clock::time_point eq_start = std::chrono::steady_clock::now();

  if(flag == 0){
    auto rng = default_random_engine {};
    for(int i = 0; i < buffer_size; i++){
      for(int j = 0; j < number_of_parties; j++){
        scalarShare r_prime_prime;
        shuffle(std::begin(bitters), std::end(bitters), rng);
        for(int inner = 0; inner < 40; inner ++){
          scalarShare curr = bitters.at(inner);
          auto c = powerMod(2, inner, (bigint(1) << 40));
          r_prime_prime[0] += curr[0] * c;
          r_prime_prime[1] += curr[1] * c;
        }
        rrShares.at(i).push_back(r_prime_prime);
      }
    }
  }
  else {
    for(int i = 0; i < buffer_size; i++){
      for(int j = 0; j < number_of_parties; j++){
        scalarShare _, r;
        prep.get_two(DATA_INVERSE, _, r);
        rrShares.at(i).push_back(r);
      }
    }
  }
  vector<vector<scalarShare>> rShares(buffer_size);
  for(int i = 0; i < buffer_size; i++) {
    vector<vector<scalarShare>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      vector<scalarShare> tmp1(40);
      for(int k = 0; k < 40 ; k++) {
        scalarShare bitShare;
        prep.get_one(DATA_BIT, bitShare);
        tmp1.at(k) = bitShare;
      }
      tmp.push_back(tmp1);
    }
    bitShares.push_back(tmp);
  }
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
      rShares.at(i).push_back(r_prime);
    }
  }
  chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
  auto PRANDM = std::chrono::duration_cast<std::chrono::milliseconds>(end - eq_start).count();
  timer_struct->PRANDM = PRANDM;
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START

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
      auto shareOfPos = scalarShare::constant(j, proc.P.my_num(), MCp.get_alphai());
      auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      cShares.at(i).push_back(c);
    }
  }
  vector<vector<CurveElement::Scalar>> c_opened(buffer_size);

  for(int i = 0; i < buffer_size; i++) {
    MCp.POpen_Begin(c_opened.at(i), cShares.at(i), extra_player);
    MCp.POpen_End(c_opened.at(i), cShares.at(i), extra_player);
    MCp.Check(extra_player);
  }
  vector<vector<vector<CurveElement::Scalar>>> c_bits;

  for(int i = 0; i < buffer_size; i++) {
    vector<vector<CurveElement::Scalar>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      bigint val(c_opened.at(i).at(j));
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
      tmp.push_back(tmp1);
    }
    c_bits.push_back(tmp);
  }

  vector<vector<vector<scalarShare>>> d_bits = bitShares;

  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      for(int k = 0; k < 40; k++) {
        CurveElement::Scalar two = 2;
        auto r = bitShares.at(i).at(j).at(k);

        auto c = scalarShare::constant(c_bits.at(i).at(j).at(k), proc.P.my_num(), MCp.get_alphai());
        auto d = c + r - two * (c_bits.at(i).at(j).at(k) * r);

        d_bits.at(i).at(j).at(k) = d;
      }
    }
  }
  vector<vector<scalarShare>> z(buffer_size);
  auto onlineEQstart = std::chrono::steady_clock::now();
  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      auto r = d_bits.at(i).at(j).at(0);
      for(int k = 1; k < 40; k++) {
        protocol.init_mul();
        protocol.prepare_mul(d_bits.at(i).at(j).at(k),r);
        protocol.start_exchange();
        protocol.stop_exchange();
        protocol.check();
        auto d = d_bits.at(i).at(j).at(k) + r - protocol.finalize_mul();
        r = d;
      }
      auto one = scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
      tuples.at(i).eq_bit_shares.push_back(one - r);
    }
  }

  end = std::chrono::steady_clock::now();
  auto equality_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - eq_start).count();
  auto equality_online_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - onlineEQstart).count();
  timer_struct->EQ_TEST_ALL = equality_testing;
  timer_struct->EQ_TEST_TRIPLE_CONSUME = equality_online_testing;
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END



  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
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
  protocol.check();
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j ++){
      auto tmp = protocol.finalize_mul();
      w_mul_const_sub_b.at(i).push_back(tmp);
    }
    tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  }

  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j++){
      auto qVal = qs.at(i).at(j)[0]; //.get_share();
      auto qMAC = qs.at(i).at(j)[1]; // .get_mac();
      auto qG = G.operator*(qVal);
      pointShare qGShare;
      qGShare[0] = qG; //.set_share(qG);
      qGShare[1] = qMAC; //.set_mac(G.operator*(qMAC));
      auto tmp = w_mul_const_sub_b.at(i).at(j);
      auto wconstShare = tmp[0]; //.get_share();
      auto wconstMAC = tmp[1]; //.get_mac();
      auto wConstP = publicKeys.at(j).operator*(wconstShare);
      pointShare stuffP;
      stuffP[0] = wConstP; //.set_share(wConstP);
      stuffP[1] = publicKeys.at(j).operator*(wconstMAC); //.set_mac(publicKeys.at(j).operator*(wconstMAC));
      auto roll = qGShare + stuffP;

      tuples.at(i).secret_L.push_back(roll);

      unsigned char h[crypto_hash_sha512_BYTES];
      CurveElement::get_hash(h, publicKeys.at(j));
      CurveElement hP = CurveElement::hash_to_group(h);

      auto qhP = hP.operator*(qVal);
      pointShare qhPShare;
      qhPShare[0] = qhP; //.set_share(qhP);
      qhPShare[1] = hP.operator*(qMAC); //.set_mac(hP.operator*(qMAC));
      auto wConstI = I.operator*(wconstShare);
      pointShare stuffI;
      stuffI[0] = wConstI; //.set_share(wConstI);
      stuffI[1] = I.operator*(wconstMAC); //.set_mac(I.operator*(wconstMAC));
      roll = qhPShare + stuffI;
      tuples.at(i).secret_R.push_back(roll);
    }
  }
  end = std::chrono::steady_clock::now();
  auto sign_preprocessing = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  timer_struct->q_w_L_R = sign_preprocessing;
  timer.stop();
    cout << "Generated " << buffer_size << " tuples in " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}

template<template<class U> class T>
void preprocessing_shamir(vector<RSIGTuple<T>>& tuples, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I, T<CurveElement::Scalar> s, bench_coll *timer_struct, int flag){
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
  vector<scalarShare> bitters(40);
  if (flag == 0){
    prep.buffer_bits();
    for(int i = 0; i < 40; i ++){
      scalarShare teso;
      prep.get_one(DATA_BIT, teso);
      bitters.at(i) = teso;
    }
  }

  vector<vector<vector<scalarShare>>> bitShares;
  vector<vector<scalarShare>> rrShares(buffer_size);
  int number_of_parties = 6;
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  //PRANDMULT
  chrono::steady_clock::time_point eq_start = std::chrono::steady_clock::now();

  if(flag == 0){
    auto rng = default_random_engine {};
    for(int i = 0; i < buffer_size; i++){
      for(int j = 0; j < number_of_parties; j++){
        scalarShare r_prime_prime;
        shuffle(std::begin(bitters), std::end(bitters), rng);
        for(int inner = 0; inner < 40; inner ++){
          scalarShare curr = bitters.at(inner);
          auto c = powerMod(2, inner, (bigint(1) << 40));
          r_prime_prime += curr * c;
        }
        rrShares.at(i).push_back(r_prime_prime);
      }
    }
  }
  else {
    for(int i = 0; i < buffer_size; i++){
      for(int j = 0; j < number_of_parties; j++){
        scalarShare _, r;
        prep.get_two(DATA_INVERSE, _, r);
        rrShares.at(i).push_back(r);
      }
    }
  }
  vector<vector<scalarShare>> rShares(buffer_size);
  for(int i = 0; i < buffer_size; i++) {
    vector<vector<scalarShare>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      vector<scalarShare> tmp1(40);
      for(int k = 0; k < 40 ; k++) {
        scalarShare bitShare;
        prep.get_one(DATA_BIT, bitShare);
        tmp1.at(k) = bitShare;
      }
      tmp.push_back(tmp1);
    }
    bitShares.push_back(tmp);
  }
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
      rShares.at(i).push_back(r_prime);
    }
  }
  chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
  auto PRANDM = std::chrono::duration_cast<std::chrono::milliseconds>(end - eq_start).count();
  timer_struct->PRANDM = PRANDM;
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START
  //EQUALITY TESTING REST START

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
      auto shareOfPos = scalarShare::constant(j, proc.P.my_num(), MCp.get_alphai());
      auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      cShares.at(i).push_back(c);
    }
  }
  vector<vector<CurveElement::Scalar>> c_opened(buffer_size);

  for(int i = 0; i < buffer_size; i++) {
    MCp.POpen_Begin(c_opened.at(i), cShares.at(i), extra_player);
    MCp.POpen_End(c_opened.at(i), cShares.at(i), extra_player);
    MCp.Check(extra_player);
  }
  vector<vector<vector<CurveElement::Scalar>>> c_bits;

  for(int i = 0; i < buffer_size; i++) {
    vector<vector<CurveElement::Scalar>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      bigint val(c_opened.at(i).at(j));
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
      tmp.push_back(tmp1);
    }
    c_bits.push_back(tmp);
  }

  vector<vector<vector<scalarShare>>> d_bits = bitShares;

  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      for(int k = 0; k < 40; k++) {
        CurveElement::Scalar two = 2;
        auto r = bitShares.at(i).at(j).at(k);

        auto c = scalarShare::constant(c_bits.at(i).at(j).at(k), proc.P.my_num(), MCp.get_alphai());
        auto d = c + r - two * (c_bits.at(i).at(j).at(k) * r);

        d_bits.at(i).at(j).at(k) = d;
      }
    }
  }
  vector<vector<scalarShare>> z(buffer_size);
  auto onlineEQstart = std::chrono::steady_clock::now();
  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
      auto r = d_bits.at(i).at(j).at(0);
      for(int k = 1; k < 40; k++) {
        protocol.init_mul();
        protocol.prepare_mul(d_bits.at(i).at(j).at(k),r);
        protocol.start_exchange();
        protocol.stop_exchange();
        protocol.check();
        auto d = d_bits.at(i).at(j).at(k) + r - protocol.finalize_mul();
        r = d;
      }
      auto one = scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
      tuples.at(i).eq_bit_shares.push_back(one - r);
    }
  }

  end = std::chrono::steady_clock::now();
  auto equality_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - eq_start).count();
  auto equality_online_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - onlineEQstart).count();
  timer_struct->EQ_TEST_ALL = equality_testing;
  timer_struct->EQ_TEST_TRIPLE_CONSUME = equality_online_testing;
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END
  //EQUALITY TESTING REST END

  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  //Rest takes care of making q, w, L and R values.
  chrono::steady_clock::time_point  begin = std::chrono::steady_clock::now();
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
  protocol.check();
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j ++){
      auto tmp = protocol.finalize_mul();
      w_mul_const_sub_b.at(i).push_back(tmp);
    }
    tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  }

  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j++){
      auto qVal = qs.at(i).at(j); //.get_share();
      auto qG = G.operator*(qVal);
      pointShare qGShare;
      qGShare = qG; //.set_share(qG);
      auto tmp = w_mul_const_sub_b.at(i).at(j);
      auto wconstShare = tmp; //.get_share();
      auto wConstP = publicKeys.at(j).operator*(wconstShare);
      pointShare stuffP;
      stuffP = wConstP; //.set_share(wConstP);
      auto roll = qGShare + stuffP;

      tuples.at(i).secret_L.push_back(roll);

      unsigned char h[crypto_hash_sha512_BYTES];
      CurveElement::get_hash(h, publicKeys.at(j));
      CurveElement hP = CurveElement::hash_to_group(h);

      auto qhP = hP.operator*(qVal);
      pointShare qhPShare;
      qhPShare = qhP; //.set_share(qhP);
      auto wConstI = I.operator*(wconstShare);
      pointShare stuffI;
      stuffI = wConstI; //.set_share(wConstI);
      roll = qhPShare + stuffI;
      tuples.at(i).secret_R.push_back(roll);
    }
  }
  end = std::chrono::steady_clock::now();
  auto sign_preprocessing = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  timer_struct->q_w_L_R = sign_preprocessing;
  timer.stop();
    cout << "Generated " << buffer_size << " tuples in " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}

