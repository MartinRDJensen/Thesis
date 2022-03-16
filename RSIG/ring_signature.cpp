#include "ECDSA/CurveElement.h"
#include "Tools/random.h"
#include <iostream>
#include <tuple>
#include <typeinfo>
#include <vector>
#include "Math/gfp.hpp"

using namespace std;
CurveElement generator = CurveElement::random_scalar_element();
int n = 5;
struct sign_values{
    CurveElement I;
    CurveElement x;
    CurveElement P;
    std::vector<CurveElement> L_prime;
    std::vector<CurveElement> R_prime;
    std::vector<CurveElement> q_values;
    std::vector<CurveElement> w_values;
    std::vector<CurveElement> L_values;
    std::vector<CurveElement> R_values;
    std::vector<CurveElement> c_values;
    std::vector<CurveElement> r_values;
};

CurveElement get_hash(CurveElement to_hash){
    CurveElement I = to_hash;
    octetStream os = I.hash(crypto_core_ristretto255_HASHBYTES);
    I.pack(os);
    I.unpack(os);
    return I;
}

std::tuple<CurveElement, CurveElement, CurveElement> gen() { 
    CurveElement sk = CurveElement::random_scalar_element();
    cout << "sk " << sk << endl;
    CurveElement pk = sk.new_mult(generator); //CurveElement::base_mult(sk);
    cout << "pk is " << pk << std::endl;

    CurveElement I = get_hash(pk);
  
    cout << "I is " << I << std::endl;

    return std::make_tuple(sk, pk, I.new_mult(sk));
}



CurveElement compute_challenge(int n, sign_values* v, bool verifying = false){
    
    if (!verifying) { 
    unsigned char out[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
        for(int i = 0; i < n*2; i++){
            if (i < n){
                crypto_hash_sha512_update(&state, v->L_values.at(i).get(), sizeof(v->L_values.at(i)));
            } else {
                crypto_hash_sha512_update(&state, v->R_values.at(i - n).get(), sizeof(v->R_values.at(i - n)));
            }
        }
    crypto_hash_sha512_final(&state, out);
    CurveElement res = CurveElement::hash_to_group(out);
    return res;
    } else {
    unsigned char out_prime[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state_prime;
    crypto_hash_sha512_init(&state_prime);
        for(int i = 0; i < n*2; i++){
            if (i < n){
                crypto_hash_sha512_update(&state_prime, v->L_prime.at(i).get(), sizeof(v->L_prime.at(i)));
            } else {
                crypto_hash_sha512_update(&state_prime, v->R_prime.at(i-n).get(), sizeof(v->R_prime.at(i-n)));
            }
        }
    crypto_hash_sha512_final(&state_prime, out_prime);
    CurveElement res = CurveElement::hash_to_group(out_prime);
    return res;
    } 
    
}



void split_c(sign_values* v){
    CurveElement c = compute_challenge(n, v);
    //cout << "The challenge is found to be: NOT REDUCED " << c << endl;
    c = c.reduce();
    //cout << "----------------------------------------" << endl;
    //cout << "The challenge is found to be: REDUCED " << c << endl;
    //cout << "----------------------------------------" << endl;
    for(int i = 0; i < n; i++ ){
        if(i == 3){
            CurveElement tmp;
            for(int j = 0; j < n; j++){     
                if(j != 3){
                    tmp = tmp.new_add(v->w_values.at(j));
                }
            }
            v->c_values.at(i) = c.new_sub(tmp); // tmp.operator-(v->w_values[i]);
        } else {
            v->c_values.at(i) = v->w_values.at(i);
        }
    }
    
}

void set_r_values(CurveElement x, sign_values* v){
    for(int i = 0; i < n; i++){
        if(i == 3){
            CurveElement tmp = v->c_values.at(i).new_mult(x);
            v->r_values.at(i) = v->q_values.at(i).new_sub(tmp); 
        } else {
           v->r_values.at(i) = v->q_values.at(i); 
        }
       
    }
}

bool verify(sign_values* v){
    for(int i = 0; i < n; i++){

        CurveElement rG = v->r_values.at(i).new_mult(generator); //CurveElement::base_mult(Responses[i]);
        CurveElement cP = v->P.new_mult(v->c_values.at(i)); 
        v->L_prime.at(i) = rG.new_add(cP);
        
        CurveElement h = get_hash(v->P);
        CurveElement rH = h.new_mult(v->r_values.at(i));
        CurveElement cI = v->I.new_mult(v->c_values.at(i));

        v->R_prime.at(i) = rH.new_add(cI);
        std::cout << "We are at index i = " << i << std::endl;
        std::cout << "Value of L_prime: " << v->L_prime[i] << " == " << v->L_values[i] << " is L" << std::endl;
        std::cout << "Value of R_prime: " << v->R_prime[i] << " == " << v->R_values[i] << " is R" << std::endl;
        std::cout << "RPRIME == R?: " << v->R_prime[i].operator==(v->R_values[i]) << std::endl;
        std::cout << "LPRIME == L?: " << v->L_prime[i].operator==(v->L_values[i]) << std::endl;
    }


    CurveElement challenge_prime = compute_challenge(n, v, true);
    CurveElement challenge_prime_reduce = challenge_prime.reduce();
    /*std::cout << "------------------------------------------" << std::endl;
    std::cout << "unpadded: " << c_padded << "=?=" << c_verf_padded << std::endl;
    std::cout << "------------------------------------------" << std::endl;*/
    CurveElement toAssert;
    std::cout << "SUMMING THE C_VALUES" << std::endl;
    for(int i = 0; i < n; i++){
        toAssert = toAssert.new_add(v->c_values.at(i));
    }
    std::cout << "res is: " << toAssert << std::endl;
    std::cout << "challenge_prime: "  << challenge_prime << std::endl;
    std::cout << "challenge_prime_reduce: "  << challenge_prime_reduce << std::endl;
    assert(challenge_prime_reduce.operator==(toAssert));

    return true;
}

sign_values j(int n, CurveElement x,CurveElement P, CurveElement I){
    sign_values v;
    v.x = x;
    v.P = P;
    v.I = I;
    
    for (int i = 0; i < n; i++){
        v.q_values.push_back(CurveElement::random_scalar_element());
        v.w_values.push_back(CurveElement::random_scalar_element());
        v.R_values.push_back(CurveElement::random_scalar_element());
        v.L_values.push_back(CurveElement::random_scalar_element());
        v.r_values.push_back(CurveElement::random_scalar_element());
        v.c_values.push_back(CurveElement::random_scalar_element());
        v.R_prime.push_back(CurveElement::random_scalar_element());
        v.L_prime.push_back(CurveElement::random_scalar_element());
        
        
        CurveElement h = get_hash(P);
        CurveElement qG = v.q_values.at(i).new_mult(generator); //CurveElement::base_mult(qs[i]);
        CurveElement qHP = h.new_mult(v.q_values.at(i));
        if(3 == i) {
            v.L_values.at(i) = qG;
            v.R_values.at(i) = qHP;
        } else {
            //cout << "pk is " << pk << " and w[i] is " << ws[i] << endl;
            //cout << "I is " << I << " and w[i] is " << ws[i] << endl;
            v.L_values.at(i) = qG.new_add(P.new_mult(v.w_values.at(i)));
            v.R_values.at(i) = qHP.new_add(I.new_mult(v.w_values.at(i)));
        }
    }
    return v;
}


int main() {
    CurveElement::init();
    auto keypair = gen();


    sign_values v = j(n,get<0>(keypair), get<1>(keypair), get<2>(keypair));
    //v = j(n,get<0>(keypair), get<1>(keypair), get<2>(keypair));
    
    split_c(&v);

    set_r_values(get<0>(keypair), &v);
    bool verifies = verify(&v);
    assert(verifies);


    CurveElement::Scalar k;
    CurveElement::Scalar p;
    PRNG G;
    //octet seed[SEED_SIZE];
    G.SetSeed(G);
    k.almost_randomize(G);
    p.almost_randomize(G);
    cout << "k is " << k << endl;
    cout << "p is " << p << endl;
    CurveElement base(1);
    cout << base.operator*(p) << endl;
    //cout << get<0>(keypair) << " " << get<1>(keypair) << " " << get<2>(keypair) << endl;
    

   
    //std::cout << c2.Scalar() << std::endl;

    return 0;
}