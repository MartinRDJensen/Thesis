#include "CurveElement.h"
#include "Tools/Bundle.h"
//#include "preprocessing.hpp"
#include "Math/gfp.hpp"
#include <vector>
#include "party.h"
CurveElement generator(1);

class RingSignature{
public:
  CurveElement keyImage;
  std::vector<CurveElement::Scalar> challenges;
  std::vector<CurveElement::Scalar> responses;
};

CurveElement::Scalar compute_challenge(unsigned char* m, std::vector<CurveElement> L, std::vector<CurveElement> R){
  unsigned char out[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_state state;
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, m, crypto_core_ristretto255_BYTES);

  for(vector<int>::size_type i = 0; i < L.size()*2; i++){
    if (i < L.size()){
      crypto_hash_sha512_update(&state, L.at(i).get(),crypto_core_ristretto255_BYTES); //sizeof(L_prime.at(i)));
    } else {
      crypto_hash_sha512_update(&state, R.at(i - R.size()).get(), crypto_core_ristretto255_BYTES); //sizeof(R_prime.at(i-n)));
    }
  }
  crypto_hash_sha512_final(&state, out);
  CurveElement::Scalar res = hash_to_scalar(out);
  return res;
}

SignatureTransaction* genTransaction(CurveElement I){
  Party sender;
  Party receiver;
  BlockChain bc;
  for(int i = 0; i < 10; i++){
    BlockChainTransaction tx(i);
    tx.make_fake_tx();
    bc.bc_add_transaction(tx);
  }

  SignatureTransaction* sign_tx = new SignatureTransaction(1000, receiver.public_key_A, receiver.public_key_B, I);
  sign_tx->sample_destination_keys(4, bc);

  // Burde bruge dest og one time private key i stedet for
  return sign_tx;
}

std::vector<CurveElement> genPublicKeys(int n, CurveElement pk){
  vector<CurveElement> publicKeys;
  publicKeys.push_back(pk);
  for (int i = 0; i < n; i++) {
    auto tmp_keys = gen();
    publicKeys.push_back(get<1>(tmp_keys));
  }
  return publicKeys;
}

std::vector<CurveElement::Scalar> genShares(int n, CurveElement::Scalar value){
  std::vector<CurveElement::Scalar> shares;
  for(int i = 0; i < n; i++){
    auto tmp = SeededPRNG().get<CurveElement::Scalar>();
    if(i == n-1){
      CurveElement::Scalar res = value;
      for(CurveElement::Scalar var : shares){
        res = res - var;
      }
      shares.push_back(res);
    } else { shares.push_back(tmp); }
  }
  return shares;
}

RingSignature sign(SignatureTransaction* tx, CurveElement::Scalar x, vector<CurveElement> P, CurveElement I){
  RingSignature signature;
  std::vector<CurveElement::Scalar> q_values;
  std::vector<CurveElement::Scalar> w_values;
  std::vector<CurveElement> L;
  std::vector<CurveElement> R;
  std::vector<CurveElement::Scalar> c_values;
  std::vector<CurveElement::Scalar> r_values;

  for (vector<int>::size_type i = 0; i < P.size(); i++){
    q_values.push_back(SeededPRNG().get<CurveElement::Scalar>());
    w_values.push_back(SeededPRNG().get<CurveElement::Scalar>());

    unsigned char h[crypto_hash_sha512_BYTES];
    CurveElement::get_hash(h, P.at(i));
    CurveElement hP = CurveElement::hash_to_group(h);

    CurveElement qG = generator.operator*(q_values.at(i));
    CurveElement qHP = hP.operator*(q_values.at(i));
    if(0 == i) {
        L.push_back(qG);
        R.push_back(qHP);
    } else {
        L.push_back(qG.operator+(P.at(i).operator*(w_values.at(i))));
        R.push_back(qHP.operator+(I.operator*(w_values.at(i))));
    }
  }

  //måske til pointer?
  unsigned char* m = reinterpret_cast<unsigned char*>(tx);
  CurveElement::Scalar c = compute_challenge(m, L, R);
  for(vector<int>::size_type i = 0; i < P.size(); i++ ){
    if(i == 0){
      CurveElement::Scalar zero_scalar;
      for(vector<int>::size_type j = 0; j < P.size(); j++){
          if(j != 0){
              zero_scalar = zero_scalar + w_values.at(j);
        }
      }
     c_values.push_back(c - zero_scalar);
    } else {
      c_values.push_back(w_values.at(i));
    }
  }
  for(vector<int>::size_type i = 0; i < P.size(); i++){
   if(i == 0){
      CurveElement::Scalar tmp = x * c_values.at(i);
      r_values.push_back(q_values.at(i) - tmp);
    } else {
      r_values.push_back(q_values.at(i));
    }
  }
  signature.keyImage = I;
  signature.challenges = c_values;
  signature.responses = r_values;
  return signature;
}

bool check(SignatureTransaction* tx, RingSignature signature, std::vector<CurveElement> P){
  Timer timer;
  timer.start();
  std::vector<CurveElement> R;
  std::vector<CurveElement> L;

  for(vector<int>::size_type i = 0; i < P.size(); i++){
    CurveElement rG = generator.operator*(signature.responses.at(i));
    CurveElement cP = P.at(i).operator*(signature.challenges.at(i));
    L.push_back(rG.operator+(cP));

    unsigned char h[crypto_hash_sha512_BYTES];
    CurveElement::get_hash(h, P.at(i));
    CurveElement hP = CurveElement::hash_to_group(h);
    CurveElement rH = hP.operator*(signature.responses.at(i));
    CurveElement cI = signature.keyImage.operator*(signature.challenges.at(i));
    R.push_back(rH.operator+(cI));
  }

  unsigned char* m = reinterpret_cast<unsigned char*>(tx);
  CurveElement::Scalar challenge_prime = compute_challenge(m, L, R);
  CurveElement::Scalar rebuildChallenge;
  for(vector<int>::size_type i = 0; i < P.size(); i++){
    rebuildChallenge = rebuildChallenge + signature.challenges.at(i);
  }
  cout << "Final verification check becomes" << endl;
  cout << challenge_prime << "=?=" << rebuildChallenge << endl;
  assert(challenge_prime.operator==(rebuildChallenge));
  std::cout << "Offline checking took: " << timer.elapsed() * 1e3 << " ms. " << std::endl;
  return true;
}

int main(){
  auto test_keys = gen();
  SignatureTransaction* tx = genTransaction(get<2>(test_keys));
  auto pkSet = genPublicKeys(5, get<1>(test_keys));
  assert(check(tx, sign(tx, get<0>(test_keys), pkSet, get<2>(test_keys)), pkSet));
  std::cout << "Assertion passed" << std::endl;

  auto share = genShares(10, get<0>(test_keys));
  CurveElement::Scalar tmp;
  std::cout << "init tmp: " << tmp << std::endl;
  for(CurveElement::Scalar var : share)
  {
    tmp = tmp + var;
  }
  assert(tmp == get<0>(test_keys));
}


