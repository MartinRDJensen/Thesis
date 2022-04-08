#include "util.h"
CurveElement G(1);


CurveElement::Scalar crypto_hash(unsigned char *m,
                                       std::vector<CurveElement> L,
                                       std::vector<CurveElement> R) {
  unsigned char out[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, m, crypto_core_ristretto255_BYTES);

  for (vector<int>::size_type i = 0; i < L.size() * 2; i++) {
    if (i < L.size()) {
      crypto_hash_sha512_update(
          &state, L.at(i).get(),
          sizeof(L_prime.at(i)));
          crypto_core_ristretto255_BYTES); // sizeof(L_prime.at(i)));
    } else {
      crypto_hash_sha512_update(
          &state, R.at(i - R.size()).get(),
          crypto_core_ristretto255_BYTES); // sizeof(R_prime.at(in)));
    }
  }
  crypto_hash_sha512_final(&state, out);
  cout << "out is " << out << endl;
  CurveElement::Scalar res = hash_to_scalar(out);
  return res;
}

CurveElement::Scalar hash_to_scalar(const unsigned char* h) {
    auto& tmp = bigint::tmp;
    mpz_import(tmp.get_mpz_t(), crypto_hash_sha512_BYTES, -1, 1, 0, 0, h);
    return tmp;
}


std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen(int skVal) {
    CurveElement::Scalar sk = skVal;

    CurveElement::init();
   // PRNG random(seed);
    //auto sk = random.get<CurveElement::Scalar>();
    //auto sk = SeededPRNG().get<CurveElement::Scalar>();
    CurveElement pk = G.operator*(sk);

    unsigned char h[crypto_hash_sha512_BYTES];
    CurveElement::get_hash(h, pk);
    CurveElement hP = CurveElement::hash_to_group(h);
    CurveElement I = hP.operator*(sk);
    /*
    cout << "From running gen() we get the following:" << endl;
    cout << "sk " << sk << endl;
    cout << "ged is " << generator << endl;
    cout << "pk is " << pk << std::endl;
    cout << "I is " << I << endl;*/
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




