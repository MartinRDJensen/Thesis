#include "util.h"

CurveElement G(1);

CurveElement::Scalar crypto_hash(unsigned char *m,
                                       std::vector<CurveElement> L,
                                       std::vector<CurveElement> R) {
  unsigned char out[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, m, strlen((char*)m));

  for (vector<int>::size_type i = 0; i < L.size() * 2; i++) {
    if (i < L.size()) {
      crypto_hash_sha512_update(
          &state, L.at(i).get(),
             // sizeof(L.at(i)));
          crypto_core_ristretto255_BYTES); // sizeof(L_prime.at(i)));
    } else {
      crypto_hash_sha512_update(
          &state, R.at(i - R.size()).get(),
             // sizeof(R.at(i-R.size())));
          crypto_core_ristretto255_BYTES);// sizeof(R_prime.at(in)));
    }
  }
  crypto_hash_sha512_final(&state, out);
  CurveElement::Scalar res = hash_to_scalar(out);
  return res;
}

CurveElement::Scalar hash_to_scalar(const unsigned char* h) {
    auto& tmp = bigint::tmp;
    mpz_import(tmp.get_mpz_t(), crypto_hash_sha512_BYTES, -1, 1, 0, 0, h);
    return tmp;
}

void print_timers(bench_coll* timer_struct, int buffer_size){
  cout << "PRANDM took: " << timer_struct->PRANDM << " miliseconds." << endl;
  cout << "PRANDM took: " << (float) timer_struct->PRANDM / (float) 1000 << " seconds." << endl;
  cout << "Rest of EQ took: " << timer_struct->EQ_TEST_ALL << " miliseconds." << endl;
  cout << "Rest of EQ took: " << (float) timer_struct->EQ_TEST_ALL / (float) 1000 << " seconds." << endl;
  cout << "Triple consuming EQ took: " << timer_struct->EQ_TEST_TRIPLE_CONSUME << " miliseconds." << endl;
  cout << "Triple consuming EQ took: " << (float) timer_struct->EQ_TEST_TRIPLE_CONSUME / (float) 1000 << " seconds." << endl;
  cout << "q,w,L,R generation took: " << timer_struct->q_w_L_R << " miliseconds." << endl;
  cout << "q,w,L,R generation took: " << (float) timer_struct->q_w_L_R / (float) 1000 << " seconds." << endl;
  cout << "Average sign took: " << (float) timer_struct->buffer_size_sign / (float) buffer_size<< " miliseconds." << endl;
  cout << "Average sign took: " << ((float) timer_struct->buffer_size_sign / (float) buffer_size) / (float) 1000 << " seconds." << endl;
  cout << "Average verf took: " << (float) timer_struct->buffer_size_verf / (float) buffer_size << " miliseconds." << endl;
  cout << "Average verf took: " << ((float) timer_struct->buffer_size_verf / (float) buffer_size) / (float) 1000 << " seconds." << endl;
  cout << "Doing online checking " << buffer_size << " times took " << timer_struct->total_online << " miliseconds" << endl;
  cout << "Average online checking took " << (float) timer_struct->total_online / (float) buffer_size << " seconds" << endl;
  cout << "Doing offline checking " << buffer_size << " times took " << timer_struct->total_offline << " miliseconds" << endl;
  cout << "Average offline checking took " << (float) timer_struct->total_offline / (float) buffer_size << " seconds" << endl;
  cout << "Total amount of bytes sent for " << buffer_size << " online checks is " << timer_struct->total_online_bytes << " bytes" << endl;
  cout << "Average amount of bytes sent for online check is " << (float) timer_struct->total_online_bytes / (float) buffer_size << " bytes" << endl;
}

std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen(CurveElement::Scalar sk) {
    //CurveElement::Scalar sk = skVal;

    CurveElement::init();
   // PRNG random(seed);
    //auto sk = random.get<CurveElement::Scalar>();
    //auto sk = SeededPRNG().get<CurveElement::Scalar>();
    CurveElement pk = G.operator*(sk);

    unsigned char h[crypto_hash_sha512_BYTES];
    CurveElement::get_hash(h, pk);
    CurveElement hP = CurveElement::hash_to_group(h);
    CurveElement I = hP.operator*(sk);
    return std::make_tuple(sk, pk, I);
}


std::vector<CurveElement> genPublicKeys(int n, CurveElement pk) {
  vector<CurveElement> publicKeys;
  publicKeys.push_back(pk);
  for (int i = 0; i < n; i++) {
    auto tmp_keys = gen(i+5);
    publicKeys.push_back(get<1>(tmp_keys));
  }
  return publicKeys;
}


