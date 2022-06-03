#include "Tools/Bundle.h"
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
std::vector<std::vector<CurveElement::Scalar>> e_w_minus_a_shares;
std::vector<std::vector<CurveElement::Scalar>> d_bit_minus_b_shares;

std::vector<std::vector<CurveElement::Scalar>> e_bit_minus_a_shares;
std::vector<std::vector<CurveElement::Scalar>>d_challenge_minus_b_shares;

vector<vector<CurveElement::Scalar>> e_bc_minus_a;
vector<vector<CurveElement::Scalar>> d_x_minus_b;


std::vector<CurveElement::Scalar> position_shares;
vector<vector<CurveElement::Scalar>> position_bit_shares;



vector<CurveElement::Scalar> e_w_minus_a_sum;
vector<CurveElement::Scalar> d_bit_minus_b_sum;

vector<CurveElement::Scalar> e_bit_minus_a_sum;
vector<CurveElement::Scalar> d_challenge_minus_b_sum;

  vector<CurveElement::Scalar> e_bc_minus_a_sum;
  vector<CurveElement::Scalar> d_x_minus_b_sum;

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

  // Burde bruge dest og one time privaste key i stedet for
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

std::tuple<std::vector<CurveElement>,std::vector<CurveElement>> sign(vector<CurveElement> P, CurveElement I, vector<CurveElement::Scalar> q_values, int position){
  std::vector<CurveElement> L;
  std::vector<CurveElement> R;
    for (vector<int>::size_type i = 0; i < P.size(); i++){
      unsigned char h[crypto_hash_sha512_BYTES];
      CurveElement::get_hash(h, P.at(i));
      CurveElement hP = CurveElement::hash_to_group(h);

      CurveElement qG = generator.operator*(q_values.at(i));
      CurveElement qHP = hP.operator*(q_values.at(i));
      CurveElement::Scalar z;
      if(position == 3) {
        z = c_shares.at(position) + e_w_minus_a_sum.at(i) * b_shares.at(position) + d_bit_minus_b_sum.at(i) * a_shares.at(position) + e_w_minus_a_sum.at(i) * d_bit_minus_b_sum.at(i);
      } else {
        z = c_shares.at(position) + e_w_minus_a_sum.at(i) * b_shares.at(position) + d_bit_minus_b_sum.at(i) * a_shares.at(position);
      }
        L.push_back(qG.operator+(P.at(i).operator*(z)));
        R.push_back(qHP.operator+(I.operator*(z)));
    }
return std::make_tuple(L, R);

}



vector<CurveElement::Scalar> sign2(CurveElement::Scalar c, vector<CurveElement> P, vector<CurveElement::Scalar> w_values, int index) {
  std::vector<CurveElement::Scalar> c_values;
  CurveElement::Scalar sum;
    for(vector<int>::size_type j = 0; j < P.size(); j++){
          sum = sum + w_values.at(j);
    }
  for(vector<int>::size_type i = 0; i < P.size(); i++ ){
      if(index == 3) {
        c_values.push_back(c - sum + w_values.at(i));
      } else {
        CurveElement::Scalar zero;
        c_values.push_back(zero - sum + w_values.at(i));
      }
    }
    return c_values;
  }




RingSignature sign3(CurveElement I, std::vector<CurveElement> P, vector<CurveElement::Scalar> c_values, vector<CurveElement::Scalar> q_values, CurveElement::Scalar a, CurveElement::Scalar b, CurveElement::Scalar c, int index) {
  RingSignature signature;
  std::vector<CurveElement::Scalar> r_values;
  CurveElement::Scalar z;
  for(vector<int>::size_type i = 0; i < P.size(); i++){
      if(index == 3) {
       z = (((c + (e_bc_minus_a_sum.at(i) * b)) + (d_x_minus_b_sum.at(i) * a)) + e_bc_minus_a_sum.at(i) * d_x_minus_b_sum.at(i));
     } else {
       z = ((c + (e_bc_minus_a_sum.at(i) * b)) + (d_x_minus_b_sum.at(i) * a));
     }
     r_values.push_back(q_values.at(i) - z);

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
    cout << "Challenge " << signature.challenges.at(i) << endl;
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

  gen_mult_tuple(number_of_parties);


  for (int j = 0; j < number_of_parties; j++) {
    vector<CurveElement::Scalar> bit_shares;
    for (vector<int>::size_type i = 0; i < pkSet.size(); i++){
      CurveElement::Scalar t = position_shares.at(j) - i;
      CurveElement::Scalar bit_share = eq_testing(t, j, i);
      bit_shares.push_back(bit_share);
    }
    position_bit_shares.push_back(bit_shares);
  }

  //Compute multi triple to multiply two shares
  //Compute epsilon and delta and open them to other parties


  for(int i = 0; i < number_of_parties; i++) {
    vector<CurveElement::Scalar> tmp_e;
    vector<CurveElement::Scalar> tmp_d;
    for(vector<int>::size_type j = 0; j < pkSet.size() ; j++) {
      CurveElement::Scalar one_minus_bit;
      if(i == 3) {
        CurveElement::Scalar one = 1;
        one_minus_bit = one - position_bit_shares.at(i).at(j);
      } else {
        CurveElement::Scalar zero;
        one_minus_bit = zero - position_bit_shares.at(i).at(j);
    }
      tmp_e.push_back(party_w_share.at(i).at(j) - a_shares.at(i));
      tmp_d.push_back(one_minus_bit - b_shares.at(i));
    }
    e_w_minus_a_shares.push_back(tmp_e);
    d_bit_minus_b_shares.push_back(tmp_d);
  }

  for(vector<int>::size_type i = 0; i < pkSet.size() ; i++) {
    CurveElement::Scalar e_sum;
    CurveElement::Scalar d_sum;
    for(int j = 0; j < number_of_parties; j++) {
      e_sum = e_sum + e_w_minus_a_shares.at(j).at(i);
      d_sum = d_sum + d_bit_minus_b_shares.at(j).at(i);
    }
    e_w_minus_a_sum.push_back(e_sum);
    d_bit_minus_b_sum.push_back(d_sum);
  }




  //Used to open L and R, since we odnt have different party classes to send and recieve
  std::vector<std::vector<CurveElement>> L_shares;
  std::vector<std::vector<CurveElement>> R_shares;
  for(int i = 0; i < number_of_parties; i++) {
    auto LR = sign(pkSet, get<2>(test_keys), party_q_share.at(i), i);
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


  for(int i = 0; i < 6; i++) {
    cout << L.at(i) << " Shares " << R.at(i) << endl;
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

  for(int i = 0; i < number_of_parties; i++) {
    vector<CurveElement::Scalar> tmp_e;
    vector<CurveElement::Scalar> tmp_d;
    for(vector<int>::size_type j = 0; j < pkSet.size() ; j++) {
      tmp_e.push_back(position_bit_shares.at(i).at(j) - a_shares.at(i));
      tmp_d.push_back(party_challenge_share.at(i).at(j) - b_shares.at(i));
    }
    e_bit_minus_a_shares.push_back(tmp_e);
    d_challenge_minus_b_shares.push_back(tmp_d);

  }
    for(vector<int>::size_type i = 0; i < pkSet.size() ; i++) {
    CurveElement::Scalar e_sum;
    CurveElement::Scalar d_sum;
    for(int j = 0; j < number_of_parties; j++) {
      e_sum = e_sum + e_bit_minus_a_shares.at(j).at(i);
      d_sum = d_sum + d_challenge_minus_b_shares.at(j).at(i);
    }
    e_bit_minus_a_sum.push_back(e_sum);
    d_challenge_minus_b_sum.push_back(d_sum);
  }
  for(int i = 0; i < number_of_parties; i++) {
    for(vector<int>::size_type j = 0; j < pkSet.size(); j++) {
      CurveElement::Scalar right_side;
      CurveElement::Scalar left_side;
      if(i == 3) {
        left_side  = c_shares.at(i) + e_bit_minus_a_sum.at(j) * b_shares.at(i) + d_challenge_minus_b_sum.at(j) * a_shares.at(i) + e_bit_minus_a_sum.at(j) * d_challenge_minus_b_sum.at(j);
        right_side = c_shares.at(i) + e_w_minus_a_sum.at(j) * b_shares.at(i) + d_bit_minus_b_sum.at(j) * a_shares.at(i) + e_w_minus_a_sum.at(j) * d_bit_minus_b_sum.at(j);
      } else {
        right_side = c_shares.at(i) + e_w_minus_a_sum.at(j) * b_shares.at(i) + d_bit_minus_b_sum.at(j) * a_shares.at(i);
        left_side = c_shares.at(i) + e_bit_minus_a_sum.at(j) * b_shares.at(i) + d_challenge_minus_b_sum.at(j) * a_shares.at(i);
      }
        party_challenge_share.at(i).at(j) = right_side + left_side;
    }
  }

  CurveElement::Scalar summ;
  for(vector<int>::size_type i = 0; i < pkSet.size() ; i++) {
    CurveElement::Scalar sum;
    for(int j = 0; j < number_of_parties; j++) {
      sum = sum + party_challenge_share.at(j).at(i);
    }
    cout <<"challenge is sum " << sum << endl;
    summ = sum + summ;
  }
cout << "Overall summ should be " << summ << endl;


  for(int i = 0; i < number_of_parties; i++) {
    vector<CurveElement::Scalar> tmp_e;
    vector<CurveElement::Scalar> tmp_d;
    for(vector<int>::size_type j = 0; j < pkSet.size() ; j++) {
      tmp_e.push_back(position_bit_shares.at(i).at(j) - a_shares.at(i));
      tmp_d.push_back(party_challenge_share.at(i).at(j) - b_shares.at(i));
    }
    e_bit_minus_a_shares.at(i) = tmp_e;
    d_challenge_minus_b_shares.at(i) = tmp_d;
  }

  for(vector<int>::size_type i = 0; i < pkSet.size() ; i++) {
    CurveElement::Scalar e_sum;
    CurveElement::Scalar d_sum;
    for(int j = 0; j < number_of_parties; j++) {
      e_sum = e_sum + e_bit_minus_a_shares.at(j).at(i);
      d_sum = d_sum + d_challenge_minus_b_shares.at(j).at(i);
    }
    e_bit_minus_a_sum.at(i) = e_sum;
    d_challenge_minus_b_sum.at(i) = d_sum;
  }

  vector<vector<CurveElement::Scalar>> bit_times_challenge;

  for(int i = 0; i < number_of_parties; i++) {
    vector<CurveElement::Scalar> party_computation;
    for(vector<int>::size_type j = 0; j < pkSet.size(); j++) {
      CurveElement::Scalar z;
      if(i == 3) {
        z = c_shares.at(i) + e_bit_minus_a_sum.at(j) * b_shares.at(i) + d_challenge_minus_b_sum.at(j) * a_shares.at(i) + e_bit_minus_a_sum.at(j) * d_challenge_minus_b_sum.at(j);
      } else {
        z = c_shares.at(i) + e_bit_minus_a_sum.at(j) * b_shares.at(i) + d_challenge_minus_b_sum.at(j) * a_shares.at(i);
      }
      party_computation.push_back(z);
    }
    bit_times_challenge.push_back(party_computation);
  }


  //Compute multi triple fto multiply two shares
  //Compute epsilon and delta and open them to other parties
  for(int i = 0; i < number_of_parties; i++) {
    vector<CurveElement::Scalar> tmp_e;
    vector<CurveElement::Scalar> tmp_d;
    for(vector<int>::size_type j = 0; j < pkSet.size() ; j++) {
      tmp_e.push_back(bit_times_challenge.at(i).at(j) - a_shares.at(i));
      tmp_d.push_back(x_shares.at(i) - b_shares.at(i));
    }
    e_bc_minus_a.push_back(tmp_e);
    d_x_minus_b.push_back(tmp_d);
  }



  for(vector<int>::size_type i = 0; i < pkSet.size() ; i++) {
    CurveElement::Scalar e_sum;
    CurveElement::Scalar d_sum;
    for(int j = 0; j < number_of_parties; j++) {
      e_sum = e_sum + e_bc_minus_a.at(j).at(i);
      d_sum = d_sum + d_x_minus_b.at(j).at(i);
    }
    e_bc_minus_a_sum.push_back(e_sum);
    d_x_minus_b_sum.push_back(d_sum);
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


