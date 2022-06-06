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

static int num_threads = 1;
static int EQ_K = 40;
template<template<class U> class T>
void thread_worker(vector<T<CurveElement::Scalar>> *d_bits,
                   vector<T<CurveElement::Scalar>> *thread_vals, int ID,
                   int low, int high, SPDZ<Share<gfp_<2, 4>>> *protocol){
//                   int low, int high, SubProcessor<T<CurveElement::Scalar>>& proc){

//  auto& protocol = proc.protocol;
  auto r = d_bits->at(low);
  cout << "WE GOT ID AS: " << ID << endl;
  for(int k = low+1; k < high; k++) {
    auto curr = d_bits->at(k);
    protocol->init_mul();
    protocol->prepare_mul(curr, r);
    protocol->start_exchange();
    protocol->stop_exchange();
    protocol->check();
    auto d = curr + r - protocol->finalize_mul();
    r = d;
   /*
    protocol.init_mul();
    protocol.prepare_mul(curr, r);
    protocol.start_exchange();
    protocol.stop_exchange();
    protocol.check();
    auto d = curr + r - protocol.finalize_mul();
    r = d;*/
  }
  cout << "THREAD_VALS->at("<<ID<<")"<<endl;
  // thread_vals->at(ID) = r;
  thread_vals->at(1) = r;
}

template<template<class U> class T>
void preprocessing(vector<RSIGTuple<T>>& tuples, RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I, T<CurveElement::Scalar> s, bench_coll *timer_struct){
  bool prep_mul = opts.prep_mul;
  cout << prep_mul << endl;
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

    // auto tmpa = SeededPRNG().get<CurveElement::Scalar>();
    // cout << tmpa << endl;
    // auto squared = tmpa*tmpa;
    // cout << tmpa << endl;
    // auto old = squared.sqrRoot();
    // int bit;
    // if (old == tmpa){
    //   bit = 1;
    // } else {
    //   bit = 0;
    // }
    //
    //




  CurveElement G(1);
  std::vector<std::vector<pointShare>> L;
  std::vector<std::vector<pointShare>> R;
  cout << "in preprocessing...." << endl;
  prep.buffer_triples();
  cout << "After buffer triples" << endl;
  prep.buffer_bits();
  cout << "After buffer bits" << endl;
  vector<scalarShare> bitters(40);
  for(int i = 0; i < 40; i ++){
    scalarShare teso;
    prep.get_one(DATA_BIT, teso);
    bitters.at(i) = teso;
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
  auto rng = default_random_engine {};
  chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
  cout << "shuffle part" << endl;
  for(int i = 0; i < buffer_size; i++){
    cout << "buffersize is: " << i << endl;
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
        // for(int j = 0; j < number_of_parties; j++){
    //   scalarShare _, r;
    //   prep.get_two(DATA_INVERSE, _, r);
    // rrShares.at(i).push_back(r);
    // }
  cout << "Doing r shares" << endl;
  vector<vector<scalarShare>> rShares(buffer_size);
  for(int i = 0; i < buffer_size; i++) {
    cout << "buffersize is: " << i << endl;
    vector<vector<scalarShare>> tmp;
    for(int j = 0; j < number_of_parties; j++) {
      cout << "vector create" << endl;
      vector<scalarShare> tmp1(40);
      cout << "vector created" << endl;
      for(int k = 0; k < 40 ; k++) {
        cout << "loading bits start k: " << k << endl;
        scalarShare bitShare;
        cout << "1" << endl;
        prep.get_one(DATA_BIT, bitShare);
        cout << "2" << endl;
        tmp1.at(k) = bitShare;
        cout << "3" << endl;
        //tmp1.push_back(bitShare);
        cout << "loading bits end k: " << k << endl;
      }
      tmp.push_back(tmp1);
    }
    bitShares.push_back(tmp);
  }
  cout << "Done loading bits" << endl;
  for(int i = 0; i < buffer_size; i++) {
    cout << "buffersize is: " << i << endl;
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
  cout << "Done with r shares" << endl;
  chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
  auto PRANDM = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  timer_struct->PRANDM = PRANDM;
  //EQUALITY TESTING PROTOCOL 2
  //EQUALITY TESTING PROTOCOL 2
  //EQUALITY TESTING PROTOCOL 2
  //EQUALITY TESTING PROTOCOL 2
  //EQUALITY TESTING PROTOCOL 2
  //EQUALITY TESTING PROTOCOL 2
  //EQUALITY TESTING PROTOCOL 2

  begin = std::chrono::steady_clock::now();
  cout << "Startingg cshares" << endl;
  vector<vector<scalarShare>> cShares(buffer_size);
  for(int i = 0; i < buffer_size; i++) {
    cout << "buffersize is: " << i << endl;
    for(int j = 0; j < number_of_parties; j++) {
      CurveElement::Scalar two = 1;
      for(int k = 0; k < 41; k++) {
         if( k != 0) {
            CurveElement::Scalar tmp = 2;
            two = two * tmp;
          }
      }
      auto shareOfPos = scalarShare::constant(j, proc.P.my_num(), MCp.get_alphai());
      //auto shareOfTwo_ = scalarShare::constant(two_, proc.P.my_num(), MCp.get_alphai());
      //auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      cShares.at(i).push_back(c);
    }
  }
  cout << "after Startingg cshares" << endl;
  vector<vector<CurveElement::Scalar>> c_opened(buffer_size);

  cout << "Checking c opened?" << endl;
  for(int i = 0; i < buffer_size; i++) {
    MCp.POpen_Begin(c_opened.at(i), cShares.at(i), extra_player);
    MCp.POpen_End(c_opened.at(i), cShares.at(i), extra_player);
    MCp.Check(extra_player);
  }
  cout << " afterChecking c opened?" << endl;
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
  vector<scalarShare> thread_vals(num_threads+10);
  vector<vector<scalarShare>> z(buffer_size);
  vector<thread> threads;
  cout << "Starting the rough loop" << endl;
  auto onlineEQstart = std::chrono::steady_clock::now();
  for(int i = 0; i < buffer_size; i++) {
    for(int j = 0; j < number_of_parties; j++) {
    cout << "Doing buffer size " << i << " for pk " << j << endl;
     /* for(int ID = 1; ID <= num_threads; ID++){
        int low = (EQ_K / num_threads)*(ID-1);
        int high = (EQ_K / num_threads) * ID;
        //cout << "low: " << low << " high: " << high << endl;
        if (ID == num_threads && EQ_K % num_threads != 0){
          high += 1;
        }
	cout << "ID IS: " << ID << endl;
	cout << "ID IS: " << ID << endl;
        thread testa([&] () {
          thread_worker(&d_bits.at(i).at(j), &thread_vals, ID, low, high, &protocol);
                     });
	cout << "ID IS: " << ID << endl;
	cout << "ID IS: " << ID << endl;
        threads.push_back(std::move(testa));
      }
      for(auto &th : threads){
        if (th.joinable()){
          th.join();
	      }
      }*/
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
      /*
      auto r = thread_vals.at(1);
      for(int k = 2; k < num_threads+1; k ++){
        protocol.init_mul();
        protocol.prepare_mul(thread_vals.at(k),r);
        protocol.start_exchange();
        protocol.stop_exchange();
        protocol.check();
        auto d = thread_vals.at(k) + r - protocol.finalize_mul();
        r = d;
      }*/
      auto one = scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
      tuples.at(i).eq_bit_shares.push_back(one - r);
    }
  }

  end = std::chrono::steady_clock::now();
  auto equality_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  auto equality_online_testing = std::chrono::duration_cast<std::chrono::milliseconds>(end - onlineEQstart).count();
  // std::cout << "Equality Testing Took: " << equality_testing << " miliseconds" << std::endl;
  // std::cout << "Equality Testing Took: " << (float) equality_testing / (float) 1000 << " [s]" << std::endl;
  // std::cout << "Equality online Testing Took: " << equality_online_testing << " miliseconds" << std::endl;
  // std::cout << "Equality online Testing Took: " << (float) equality_online_testing / (float) 1000 << " [s]" << std::endl;
  // std::cout << "Equality testing without the multiplication of shares part: " << equality_testing - equality_online_testing << " milliseconds" << endl;
  timer_struct->EQ_TEST_ALL = equality_testing;
  timer_struct->EQ_TEST_TRIPLE_CONSUME = equality_online_testing;
  //END OF EQUALITY TESTING PROTOCOL 2
  //END OF EQUALITY TESTING PROTOCOL 2
  //END OF EQUALITY TESTING PROTOCOL 2
  //END OF EQUALITY TESTING PROTOCOL 2
  //END OF EQUALITY TESTING PROTOCOL 2
  //END OF EQUALITY TESTING PROTOCOL 2
  //END OF EQUALITY TESTING PROTOCOL 2

  begin = std::chrono::steady_clock::now();
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
  // cout << "Generating qs, ws and computing L and Rs locally took: " << sign_preprocessing << " milliseconds" << endl;
  // cout << "Generating qs, ws and computing L and Rs locally took: " << (float) sign_preprocessing / (float) 1000<< " seconds" << endl;
  timer_struct->q_w_L_R = sign_preprocessing;
  timer.stop();
    cout << "Generated " << buffer_size << " tuples in " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}




template<template<class U> class T>
void fake(vector<RSIGTuple<T>>& tuples, RSIGOptions opts, SubProcessor<T<CurveElement::Scalar>>& proc, int buffer_size, std::vector<CurveElement> publicKeys, CurveElement I, T<CurveElement::Scalar> s, bench_coll *timer_struct){
  timer_struct->total_online += 1;
  bool prep_mul = opts.prep_mul;
  cout << prep_mul << endl;
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
  cout << "first loop" << endl;
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j++){
      scalarShare _, r;
      prep.get_two(DATA_INVERSE, _, r);
      rrShares.at(i).push_back(r);
    }
  }

  cout << "second loop" << endl;
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

  cout << "third loop" << endl;
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

  vector<vector<scalarShare>> cShares(buffer_size);

  cout << "fourth loop" << endl;

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
      //auto shareOfTwo_ = scalarShare::constant(two_, proc.P.my_num(), MCp.get_alphai());
      auto c = (s - shareOfPos) + two * rrShares.at(i).at(j) + rShares.at(i).at(j);
      cShares.at(i).push_back(c);
    }
  }

  vector<vector<CurveElement::Scalar>> c_opened(buffer_size);
  cout << "fifth loop" << endl;

  for(int i = 0; i < buffer_size; i++) {
    cout << "checking cShares.... i is: " << i << endl;
    MCp.POpen_Begin(c_opened.at(i), cShares.at(i), extra_player);
    MCp.POpen_End(c_opened.at(i), cShares.at(i), extra_player);
    MCp.Check(extra_player);
  }

  vector<vector<vector<CurveElement::Scalar>>> c_bits;
  cout << "six loop" << endl;

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
      //std::reverse(tmp1.begin(), tmp1.end());
      tmp.push_back(tmp1);
    }
    c_bits.push_back(tmp);
  }

  vector<vector<vector<scalarShare>>> d_bits = bitShares;
  cout << "seven loop" << endl;

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
  cout << "8 big loop" << endl;

  for(int i = 0; i < buffer_size; i++) {
    cout << "big loop i: " << i << endl;
    for(int j = 0; j < number_of_parties; j++) {
      scalarShare sum;
      protocol.init_mul();
      auto r = d_bits.at(i).at(j).at(0);
      for(int k = 1; k < 40; k++) {
        cout << "buffer_size: " << i << endl;
        cout << "k = " <<k << ", 1, " << "sign key is: " << j << endl;
        protocol.prepare_mul(d_bits.at(i).at(j).at(k),r);
        cout << "k = "<<  k << ", 2" << endl;
        protocol.start_exchange();
        cout << "k = "<<  k << ", 2" << endl;
        protocol.stop_exchange();
        cout << "k = "<<  k << ", 4" << endl;
        protocol.check();
        cout << "k = "<<  k << ", 5" << endl;
        cout << d_bits.at(i).at(j).at(k) << endl;
        auto d = d_bits.at(i).at(j).at(k) + r - protocol.finalize_mul();
        cout << "k = "<<  k << ", 6" << endl;
        r = d;
      }
        cout << "7" << endl;
      auto one = scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
        cout << "8" << endl;
      tuples.at(i).eq_bit_shares.push_back(one - r);
    }
  }
  // cout << "9 checking" << endl;
  //   vector<CurveElement::Scalar> noget(40);
  //   MCp.POpen_Begin(noget, tuples.at(0).eq_bit_shares, extra_player);
  //   MCp.POpen_End(noget, tuples.at(0).eq_bit_shares, extra_player);
  //   MCp.Check(extra_player);
  // cout
  //

  vector<vector<scalarShare>> qs(buffer_size), ws(buffer_size);
  vector<vector<scalarShare>> w_mul_const_sub_b(buffer_size);
  cout << "got here 1" << endl;
  auto shareOfOne =  scalarShare::constant(1, proc.P.my_num(), MCp.get_alphai());
  for(int j = 0; j < buffer_size; j++){
    for(int i = 0; i < number_of_parties; i++){
      scalarShare q, w, _tmp;
      prep.get_three(DATA_TRIPLE, q, w, _tmp);
      cout << "got data triple" << " buffer: " << i << ", party: " << j << endl;
      qs.at(j).push_back(q);
      ws.at(j).push_back(w);
    }

    tuples.at(j).q_values = qs.at(j);
    tuples.at(j).w_values = ws.at(j);

  }
  cout << "got here 2" << endl;


  // protocol.init_mul();
  // for(int i = 0; i < buffer_size; i++){
  //   for(int j = 0; j < number_of_parties; j++){
  //     protocol.prepare_mul(ws.at(i).at(j), shareOfOne - tuples.at(i).eq_bit_shares.at(j));
  //   }
  // }
  // cout << "got here 3 before start" << endl;
  // protocol.exchange();
  // cout << "got here 5" << endl;
  // protocol.check();
  // cout << "got here 6" << endl;
  // for(int i = 0; i < buffer_size; i++){
  //   for(int j = 0; j < number_of_parties; j ++){
  //     auto tmp = protocol.finalize_mul();
  //     w_mul_const_sub_b.at(i).push_back(tmp);
  //   }
  //   tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  // }
  for(int i = 0; i < buffer_size; i++){
    for(int j = 0; j < number_of_parties; j++){

    protocol.init_mul();
    protocol.prepare_mul(ws.at(i).at(j), shareOfOne - tuples.at(i).eq_bit_shares.at(j));
    protocol.start_exchange();
    protocol.stop_exchange();
    protocol.check();
    auto tmp = protocol.finalize_mul();
    w_mul_const_sub_b.at(i).push_back(tmp);
    }
    tuples.at(i).w_mul_const_sub_bit = w_mul_const_sub_b.at(i);
  }
  cout << "got here 4" << endl;

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

  timer.stop();
    cout << "Generated " << buffer_size << " tuples in " << timer.elapsed()
            << " seconds, throughput " << buffer_size / timer.elapsed() << ", "
            << 1e-3 * (P.total_comm().sent - start) / buffer_size
            << " kbytes per tuple" << endl;
    (P.total_comm() - stats).print(true);
}
