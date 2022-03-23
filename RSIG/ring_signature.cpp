#include <iostream>
#include <tuple>
#include <typeinfo>
#include <vector>
#include "RSIG/ring_signature.h"

using namespace std;
CurveElement ged(1); //CurveElement::random_scalar_element();
//int n = 5;


CurveElement::Scalar hash_to_scalar(const unsigned char* h) {
    auto& tmp = bigint::tmp;
    mpz_import(tmp.get_mpz_t(), crypto_hash_sha512_BYTES, -1, 1, 0, 0, h);
    return tmp;
}

std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen() {
    CurveElement::init();
    auto sk = SeededPRNG().get<CurveElement::Scalar>();
    CurveElement pk = ged.operator*(sk);

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



CurveElement::Scalar compute_challenge(sign_values* v, bool verifying = false){
    unsigned char out[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, v->m, crypto_core_ristretto255_BYTES);
    if (!verifying) {
        for(vector<int>::size_type i = 0; i < v->P.size()*2; i++){
            if (i < v->P.size()){
                crypto_hash_sha512_update(&state, v->L_values.at(i).get(), crypto_core_ristretto255_BYTES); //sizeof(v->L_values.at(i)));
            } else {
                crypto_hash_sha512_update(&state, v->R_values.at(i - v->P.size()).get(),crypto_core_ristretto255_BYTES); // sizeof(v->R_values.at(i - n)));
            }
        }
    } else {
        for(vector<int>::size_type i = 0; i < v->P.size()*2; i++){
            if (i < v->P.size()){
                crypto_hash_sha512_update(&state, v->L_prime.at(i).get(),crypto_core_ristretto255_BYTES); //sizeof(v->L_prime.at(i)));
            } else {
                crypto_hash_sha512_update(&state, v->R_prime.at(i - v->P.size()).get(), crypto_core_ristretto255_BYTES); //sizeof(v->R_prime.at(i-n)));
            }
        }
    }
    crypto_hash_sha512_final(&state, out);
    CurveElement::Scalar res = hash_to_scalar(out);
    return res;
}



void split_c(sign_values* v){
    CurveElement::Scalar c = compute_challenge(v);
    for(vector<int>::size_type i = 0; i < v->P.size(); i++ ){
        if(i == 0){
            CurveElement::Scalar zero_scalar;
            for(vector<int>::size_type j = 0; j < v->P.size(); j++){
                if(j != 0){
                    zero_scalar = zero_scalar + v->w_values.at(j);
                }
            }
            v->c_values.push_back(c - zero_scalar);
        } else {
            v->c_values.push_back(v->w_values.at(i));
        }
    }
}

void set_r_values(CurveElement::Scalar x, sign_values* v){
    for(vector<int>::size_type i = 0; i < v->P.size(); i++){
        if(i == 0){
            CurveElement::Scalar tmp = x * v->c_values.at(i);
            v->r_values.push_back(v->q_values.at(i) - tmp);
        } else {
           v->r_values.push_back(v->q_values.at(i));
        }

    }
}

bool verify(sign_values* v){
    for(vector<int>::size_type i = 0; i < v->P.size(); i++){
        CurveElement rG = ged.operator*(v->r_values.at(i));
        CurveElement cP = v->P.at(i).operator*(v->c_values.at(i));
        v->L_prime.push_back(rG.operator+(cP));
        unsigned char h[crypto_hash_sha512_BYTES];
        CurveElement::get_hash(h, v->P.at(i));
        CurveElement hP = CurveElement::hash_to_group(h);

        CurveElement rH = hP.operator*(v->r_values.at(i));
        CurveElement cI = v->I.operator*(v->c_values.at(i));

        v->R_prime.push_back(rH.operator+(cI));
    }

    CurveElement::Scalar challenge_prime = compute_challenge(v, true);
    CurveElement::Scalar toAssert;
    for(vector<int>::size_type i = 0; i < v->P.size(); i++){
        toAssert = toAssert + v->c_values.at(i);
    }
    cout << "Final verification check becomes" << endl;
    cout << challenge_prime << "=?=" << toAssert << endl;
    assert(challenge_prime.operator==(toAssert));
    return true;
}

sign_values j(unsigned char* m, CurveElement::Scalar x, vector<CurveElement> P, CurveElement I){
    sign_values v;
    v.x = x;
    v.P = P;
    v.I = I;
    v.m = m;
    for (vector<int>::size_type i = 0; i < v.P.size(); i++){

        v.q_values.push_back(SeededPRNG().get<CurveElement::Scalar>());
        v.w_values.push_back(SeededPRNG().get<CurveElement::Scalar>());

        unsigned char h[crypto_hash_sha512_BYTES];
        CurveElement::get_hash(h, P.at(i));
        CurveElement hP = CurveElement::hash_to_group(h);

        CurveElement qG = ged.operator*(v.q_values.at(i));
        CurveElement qHP = hP.operator*(v.q_values.at(i));
        if(0 == i) {
            v.L_values.push_back(qG);
            v.R_values.push_back(qHP);
        } else {
            v.L_values.push_back(qG.operator+(P.at(i).operator*(v.w_values.at(i))));
            v.R_values.push_back(qHP.operator+(I.operator*(v.w_values.at(i))));


        }
    }
    return v;
}

