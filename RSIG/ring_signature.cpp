#include "ECDSA/CurveElement.h"
#include "Tools/random.h"
#include <iostream>
#include <tuple>
#include <typeinfo>
#include <vector>
#include "Math/gfp.hpp"
#include <stdio.h>
#include <string.h>
#include "RSIG/ring_signature.h"

using namespace std;
CurveElement generator(1); //CurveElement::random_scalar_element();
int n = 5;

struct sign_values{
    CurveElement I;
    CurveElement x;
    CurveElement P;
    CurveElement hP;
    std::vector<CurveElement> L_prime;
    std::vector<CurveElement> R_prime;
    std::vector<CurveElement::Scalar> q_values;
    std::vector<CurveElement::Scalar> w_values;
    std::vector<CurveElement> L_values;
    std::vector<CurveElement> R_values;
    std::vector<CurveElement::Scalar> c_values;
    std::vector<CurveElement::Scalar> r_values;
};

CurveElement get_hash(CurveElement to_hash){

    unsigned char out[crypto_hash_sha512_BYTES];

    crypto_hash_sha512(out, to_hash.get(), crypto_core_ristretto255_BYTES);
    CurveElement hP = CurveElement::hash_to_group(out);

    cout << "hP is " << hP << endl;
    cout << "hP reduce is " << hP.reduce() << std::endl;

    /*
    CurveElement hP = to_hash;
    octetStream os = hP.hash(crypto_hash_sha512_BYTES);
    
    hP.pack(os);
    hP.unpack(os);
    hP.check();
    
    cout << "hhp before hash to group " << hP << endl;
    CurveElement hpp = hP.hash_to_group();

    cout << "hhp after hash to group " << hpp << endl;
    */
    // return hP.reduce(); Dette virker ikke, giver alt 0 :O
    return hP;
}

CurveElement::Scalar hash_to_scalar(const unsigned char* h) {
    auto& tmp = bigint::tmp;
    mpz_import(tmp.get_mpz_t(), crypto_hash_sha512_BYTES, -1, 1, 0, 0, h);
    return tmp;
}

std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen() { 
    CurveElement::init();
    auto sk = SeededPRNG().get<CurveElement::Scalar>();
    cout << "sk " << sk << endl;
    cout << "generator is " << generator << endl;
    CurveElement pk = generator.operator*(sk); 
    cout << "pk is " << pk << std::endl;
    
    CurveElement hP = get_hash(pk);
    cout << "hp  is " << hP << endl;
    CurveElement I = hP.operator*(sk);

    cout << "II is " << I << endl;
    return std::make_tuple(sk, pk, I);
}



CurveElement::Scalar compute_challenge(int n, sign_values* v, bool verifying = false){
    
    if (!verifying) { 
    unsigned char out[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
        for(int i = 0; i < n*2; i++){
            if (i < n){
                crypto_hash_sha512_update(&state, v->L_values.at(i).get(), crypto_core_ristretto255_BYTES); //sizeof(v->L_values.at(i)));
            } else {
                crypto_hash_sha512_update(&state, v->R_values.at(i - n).get(),crypto_core_ristretto255_BYTES); // sizeof(v->R_values.at(i - n)));
            }
        }
    crypto_hash_sha512_final(&state, out);
    CurveElement::Scalar res = hash_to_scalar(out);
    return res;
    } else {
    unsigned char out_prime[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state_prime;
    crypto_hash_sha512_init(&state_prime);
        for(int i = 0; i < n*2; i++){
            if (i < n){
                crypto_hash_sha512_update(&state_prime, v->L_prime.at(i).get(),crypto_core_ristretto255_BYTES); //sizeof(v->L_prime.at(i)));
            } else {
                crypto_hash_sha512_update(&state_prime, v->R_prime.at(i-n).get(), crypto_core_ristretto255_BYTES); //sizeof(v->R_prime.at(i-n)));
            }
        }
    crypto_hash_sha512_final(&state_prime, out_prime);
    CurveElement::Scalar res = hash_to_scalar(out_prime);
    return res;
    } 
    
}



void split_c(sign_values* v){
    CurveElement::Scalar c = compute_challenge(n, v);
    //cout << "The challenge is found to be: NOT REDUCED " << c << endl;
    //cout << "----------------------------------------" << endl;
    cout << "The challenge is found to be: REDUCED " << c << endl;
    //cout << "----------------------------------------" << endl;
    for(int i = 0; i < n; i++ ){
        if(i == 3){
            CurveElement::Scalar zero_scalar;
            for(int j = 0; j < n; j++){     
                if(j != 3){
                    zero_scalar = zero_scalar + v->w_values.at(j);
                }
            }
            v->c_values.push_back(c - zero_scalar);
            //v->c_values.push_back(c.operator-(tmp)); 
        } else {
            v->c_values.push_back(v->w_values.at(i)); 
        }
    }
    
}

void set_r_values(CurveElement::Scalar x, sign_values* v){
    for(int i = 0; i < n; i++){
        if(i == 3){
            CurveElement::Scalar tmp = x * v->c_values.at(i); 
            v->r_values.push_back(v->q_values.at(i) - tmp); 
        } else {
           v->r_values.push_back(v->q_values.at(i)); 
        }
       
    }
}

bool verify(sign_values* v){
    for(int i = 0; i < n; i++){
        CurveElement rG = generator.operator*(v->r_values.at(i));       
        CurveElement cP = v->P.operator*(v->c_values.at(i));              
        v->L_prime.push_back(rG.operator+(cP));                            
        
        CurveElement h = get_hash(v->P);
        cout << "hP is " << h << endl;
        CurveElement rH = h.operator*(v->r_values.at(i));              
        CurveElement cI = v->I.operator*(v->c_values.at(i));               

        v->R_prime.push_back(rH.operator+(cI));
        std::cout << "We are at index i = " << i << std::endl;
        std::cout << "Value of L_prime: " << v->L_prime[i] << " == " << v->L_values[i] << " is L" << std::endl;
        std::cout << "Value of R_prime: " << v->R_prime[i] << " == " << v->R_values[i] << " is R" << std::endl;
        std::cout << "RPRIME == R?: " << v->R_prime[i].operator==(v->R_values[i]) << std::endl;
        std::cout << "LPRIME == L?: " << v->L_prime[i].operator==(v->L_values[i]) << std::endl;
    }

    CurveElement::Scalar challenge_prime = compute_challenge(n, v, true);
    /*std::cout << "------------------------------------------" << std::endl;
    std::cout << "unpadded: " << c_padded << "=?=" << c_verf_padded << std::endl;
    std::cout << "------------------------------------------" << std::endl;*/
    CurveElement::Scalar toAssert;
    std::cout << "SUMMING THE C_VALUES" << std::endl;
    for(int i = 0; i < n; i++){
        toAssert = toAssert + v->c_values.at(i); 
    }
    std::cout << "res is: " << toAssert << std::endl;
    std::cout << "challenge_prime: "  << challenge_prime << std::endl;
    assert(challenge_prime.operator==(toAssert));

    return true;
}

sign_values j(int n, CurveElement::Scalar x,CurveElement P, CurveElement I){
    sign_values v;
    v.x = x;
    v.P = P;
    v.I = I;
    
    for (int i = 0; i < n; i++){
        
        v.q_values.push_back(SeededPRNG().get<CurveElement::Scalar>());
        v.w_values.push_back(SeededPRNG().get<CurveElement::Scalar>());

        /*
        v.R_values.push_back(CurveElement::random_scalar_element());
        v.L_values.push_back(CurveElement::random_scalar_element());
        v.r_values.push_back(CurveElement::random_scalar_element());
        v.c_values.push_back(CurveElement::random_scalar_element());
        v.R_prime.push_back(CurveElement::random_scalar_element());
        v.L_prime.push_back(CurveElement::random_scalar_element());
        */
        
        CurveElement h = get_hash(P);
        cout << "hP is " << h << endl;
        
        CurveElement qG = generator.operator*(v.q_values.at(i)); 
        CurveElement qHP = h.operator*(v.q_values.at(i));
        if(3 == i) {
            v.L_values.push_back(qG);
            v.R_values.push_back(qHP);
        } else {
            //cout << "pk is " << pk << " and w[i] is " << ws[i] << endl;
            //cout << "I is " << I << " and w[i] is " << ws[i] << endl;
            v.L_values.push_back(qG.operator+(P.operator*(v.w_values.at(i))));
            v.R_values.push_back(qHP.operator+(I.operator*(v.w_values.at(i))));

          
        }
    }
    return v;
}


/*    auto keypair = gen();
    Party doris;

    cout << "oihjio" << endl;
    sign_values v = j(n,get<0>(keypair), get<1>(keypair), get<2>(keypair));
    
    
    split_c(&v);
    
    set_r_values(get<0>(keypair), &v);
    cout << "oihjio" << endl;
    bool verifies = verify(&v);
    assert(verifies);
   
    PRNG G;
    G.InitSeed();


    auto k = SeededPRNG().get<CurveElement::Scalar>();
    auto p = SeededPRNG().get<CurveElement::Scalar>();
    cout << "læijhugf " << k << endl;
    cout << "læijhugf " << p << endl;
    
    CurveElement base(1);
    for(int i = 0; i < 200; i++) {
        auto k = SeededPRNG().get<P256Element::Scalar>();
        cout << "læijhugf " << k << endl;
    }
    */
