//#include "CurveElement.h"
#include "Tools/Bundle.h"
//#include "preprocessing.hpp"
//#include "Math/gfp.hpp"
#include <vector>
#include "party.h"
#include <tuple>
#include "eq.cpp"
CurveElement generator(1);


std::vector<CurveElement::Scalar> qs;
std::vector<CurveElement::Scalar> ww;

std::vector<CurveElement::Scalar> a_shares;
std::vector<CurveElement::Scalar> b_shares;
std::vector<CurveElement::Scalar> c_shares;

std::vector<CurveElement::Scalar> position_shares;




CurveElement::Scalar e;
CurveElement::Scalar d;

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

void gen_mult_tuple(int n) {
  CurveElement::Scalar a = SeededPRNG().get<CurveElement::Scalar>();
  CurveElement::Scalar b = SeededPRNG().get<CurveElement::Scalar>();
  CurveElement::Scalar c = a * b;

  a_shares = genShares(n, a);
  b_shares = genShares(n, b);
  c_shares = genShares(n, c);
}

std::tuple<std::vector<CurveElement>,std::vector<CurveElement>> sign(vector<CurveElement> P, CurveElement I, vector<CurveElement::Scalar> q_values, vector<CurveElement::Scalar> w_values, CurveElement::Scalar s, int position){
  std::vector<CurveElement> L;
  std::vector<CurveElement> R;

  for (vector<int>::size_type i = 0; i < P.size(); i++){
    CurveElement::Scalar t = s - i;
    CurveElement::Scalar bit_share = eq_testing(t, position, i);
    cout << bit_share << endl;
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

return std::make_tuple(L, R);

}



vector<CurveElement::Scalar> sign2(CurveElement::Scalar c, vector<CurveElement> P, vector<CurveElement::Scalar> w_values, int index) {
  std::vector<CurveElement::Scalar> c_values;
  RingSignature signature;
  //måske til pointer?
  for(vector<int>::size_type i = 0; i < P.size(); i++ ){
    if(i == 0){
      CurveElement::Scalar zero_scalar;
      CurveElement::Scalar hhaha = c;
      for(vector<int>::size_type j = 0; j < P.size(); j++){
        if (j != 0){
          hhaha = hhaha-w_values.at(j); 
        }
      }
      for(vector<int>::size_type j = 0; j < P.size(); j++){
          if(j != 0){
              zero_scalar = zero_scalar + w_values.at(j);
        }
      }
      assert(hhaha ==(c-zero_scalar));
      if(index == 3) { 
        cout << "index 3" << endl;
        c_values.push_back(c - zero_scalar);
      } else {
        CurveElement::Scalar bro;
        c_values.push_back(bro - zero_scalar);
      }
    } else {
      c_values.push_back(w_values.at(i));
    }
   
  }  
  
  return c_values;
}
  
RingSignature sign3(CurveElement I, std::vector<CurveElement> P, vector<CurveElement::Scalar> c_values, vector<CurveElement::Scalar> q_values, CurveElement::Scalar a, CurveElement::Scalar b, CurveElement::Scalar c, int index) {
  RingSignature signature;
  std::vector<CurveElement::Scalar> r_values;
  for(vector<int>::size_type i = 0; i < P.size(); i++){
   if(i == 0){
     CurveElement::Scalar z;
     if(index == 3) {
       z = (((c + (e * b)) + (d * a)) + e*d);
     } else {
       z = ((c + (e * b)) + (d * a));
     }
      r_values.push_back(q_values.at(i) - z);
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
  for(int i = 0; i < 6; i++) {
    cout << L.at(i) << " " << R.at(i) << endl;
    cout << " " << endl;
}
  cout << "Final verification check becomes" << endl;
  cout << challenge_prime << "=?=" << rebuildChallenge << endl;
  assert(challenge_prime.operator==(rebuildChallenge));
  std::cout << "Offline checking took: " << timer.elapsed() * 1e3 << " ms. " << std::endl;
  return true;
}

int main(){
  auto test_keys = gen();
  int number_of_parties = 10;
  CurveElement::Scalar zero;

  position_shares = genShares(number_of_parties, zero);

  SignatureTransaction* tx = genTransaction(get<2>(test_keys));
  auto pkSet = genPublicKeys(5, get<1>(test_keys));

  /*
  assert(check(tx, sign(tx, get<0>(test_keys), pkSet, get<2>(test_keys)), pkSet));
  std::cout << "Assertion passed" << std::endl;
  */

  //Make share of secret key x
  auto x_shares = genShares(number_of_parties, get<0>(test_keys));

  std::vector<std::vector<CurveElement::Scalar>> party_q_share(number_of_parties);
  std::vector<std::vector<CurveElement::Scalar>> party_w_share(number_of_parties);

  //Generate q and w
  for(vector<int>::size_type i = 0; i < pkSet.size(); i++) {
    qs.push_back(SeededPRNG().get<CurveElement::Scalar>());
    ww.push_back(SeededPRNG().get<CurveElement::Scalar>());
  }
  //Distribute shares of q amd w
  for(vector<int>::size_type i = 0; i < pkSet.size(); i++) {
    vector<CurveElement::Scalar> shares_of_q = genShares(number_of_parties, qs.at(i));
    vector<CurveElement::Scalar> shares_of_w = genShares(number_of_parties, ww.at(i));
  
    for(int j = 0; j < number_of_parties; j++) {
      party_q_share.at(j).push_back(shares_of_q.at(j));
      party_w_share.at(j).push_back(shares_of_w.at(j));
    }
  }
 
  //Used to open L and R, since we odnt have different party classes to send and recieve
  std::vector<std::vector<CurveElement>> L_shares;
  std::vector<std::vector<CurveElement>> R_shares;
  for(int i = 0; i < number_of_parties; i++) {
    auto LR = sign(pkSet, get<2>(test_keys), party_q_share.at(i), party_w_share.at(i), position_shares.at(i), i);
    L_shares.push_back(get<0>(LR));
    R_shares.push_back(get<1>(LR));
  }
  vector<CurveElement> L;
  vector<CurveElement> R;  
  for(vector<int>::size_type i = 0; i < L_shares.at(0).size(); i++) {
    CurveElement tmp_L;
    CurveElement tmp_R;
    for(int j = 0; j < number_of_parties; j++) {
      tmp_L = tmp_L.operator+(L_shares.at(j).at(i)); 
      tmp_R = tmp_R.operator+(R_shares.at(j).at(i)); 
    }
    L.push_back(tmp_L);
    R.push_back(tmp_R);
  }
  
  //Compute challenge
  unsigned char* m = reinterpret_cast<unsigned char*>(tx);
  CurveElement::Scalar challenge = compute_challenge(m, L, R);  

  cout  << "outout of hash is " << challenge << endl;
  
  
  vector<vector<CurveElement::Scalar>> party_challenge_share;
  for(int i = 0; i < number_of_parties; i++) {
    vector<CurveElement::Scalar> challenge_shares = sign2(challenge, pkSet,  party_w_share.at(i), i);
    party_challenge_share.push_back(challenge_shares);
  }
 

  vector<CurveElement::Scalar> e_shares;
  vector<CurveElement::Scalar> d_shares;

  gen_mult_tuple(number_of_parties);  
  




  //Compute multi triple to multiply two shares
  //Compute epsilon and delta and open them to other parties
  for(int i = 0; i < number_of_parties; i++) {
      e_shares.push_back(party_challenge_share.at(i).at(0) - a_shares.at(i));
      d_shares.push_back(x_shares.at(i) - b_shares.at(i));
  }
  for(int i = 0; i < number_of_parties; i++) { 
    e = e + e_shares.at(i);
    d = d + d_shares.at(i);
  }
  //Compute respones and signatures shares
  vector<RingSignature> signature_shares;
  for(int i = 0; i < number_of_parties; i++) {

    RingSignature signature = sign3(get<2>(test_keys), pkSet, party_challenge_share.at(i), party_q_share.at(i), a_shares.at(i), b_shares.at(i), c_shares.at(i), i);
    signature_shares.push_back(signature);

  }
  

  //Sum signatures
  vector<CurveElement::Scalar> challenges;
  vector<CurveElement::Scalar> responses;
  
  cout << signature_shares.size() << endl;
  cout << signature_shares.at(0).challenges.size() << endl;

  for(vector<int>::size_type i = 0; i < signature_shares.at(0).challenges.size(); i++) {
    CurveElement::Scalar tmp_challenges;
    CurveElement::Scalar tmp_responses;
    for(int j = 0; j < number_of_parties; j++) {
      tmp_challenges = tmp_challenges + signature_shares.at(j).challenges.at(i);
      tmp_responses = tmp_responses + signature_shares.at(j).responses.at(i);
    }
  challenges.push_back(tmp_challenges);
  responses.push_back(tmp_responses);
  }

  RingSignature final_signature;
  final_signature.keyImage = get<2>(test_keys);
  final_signature.challenges = challenges;
  final_signature.responses = responses;

  assert(check(tx, final_signature, pkSet));  

  /*
  CurveElement::Scalar tmp;
  std::cout << "init tmp: " << tmp << std::endl;
  for(CurveElement::Scalar var : x_shares)
  {
    tmp = tmp + var;
  }

  assert(tmp == get<0>(test_keys));
  */
}




