#include "ECDSA/CurveElement.h"
#include <iostream>
#include <tuple>
#include <typeinfo>
#include <vector>

using namespace std;
CurveElement generator = CurveElement::random_scalar_element();
int n = 6;
struct sign_values{
    bool eval;
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



std::tuple<CurveElement, CurveElement, CurveElement> gen() { 
    CurveElement sk = CurveElement::random_scalar_element();
    CurveElement pk = sk.new_mult(generator); //CurveElement::base_mult(sk);
    cout << "pk is " << pk << std::endl;

    CurveElement I = pk;
    octetStream stream = I.hash(crypto_core_ristretto255_HASHBYTES);
    I.pack(stream);
    I.unpack(stream);
    
    cout << "I is " << I << std::endl;

    return std::make_tuple(sk, pk, I.new_mult(sk));
}



CurveElement compute_challenge(int n, sign_values* v, bool verifying = false){
    
    if (!verifying) { 
    unsigned char out[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
        for(int i = 0; i < n*2; i++){
            cout << "ababab " << endl;
            if (i < n){
                crypto_hash_sha512_update(&state, v->L_values.at(i).get(), sizeof(v->L_values.at(i)));
            } else {
                crypto_hash_sha512_update(&state, v->R_values.at(i - n).get(), sizeof(v->R_values.at(i - n)));
            }
        }
    crypto_hash_sha512_final(&state, out);
    CurveElement res = CurveElement::test(out);
    return res;
    } else {
    unsigned char out_prime[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state_prime;
    crypto_hash_sha512_init(&state_prime);
        for(int i = 0; i < n*2; i++){
            std::cout << "asdjaslkdjaslædkaj" << std::endl;
            if (i < n){
                crypto_hash_sha512_update(&state_prime, v->L_prime.at(i).get(), sizeof(v->L_prime.at(i)));
            } else {
                crypto_hash_sha512_update(&state_prime, v->R_prime.at(i-n).get(), sizeof(v->R_prime.at(i-n)));
            }
        }
    crypto_hash_sha512_final(&state_prime, out_prime);
    CurveElement res = CurveElement::test(out_prime);
    return res;
    }
    
}

CurveElement get_hash(CurveElement to_hash){
    CurveElement I = to_hash;
    octetStream os = I.hash(crypto_core_ristretto255_HASHBYTES);
    I.pack(os);
    I.unpack(os);
    return I;
}

void split_c(sign_values* v){
    CurveElement c = compute_challenge(n, v);
    
    cout << "----------------------------------------" << endl;
    cout << "The challenge is found to be: NOT REDUCED " << c << endl;
    cout << "The challenge is found to be: REDUCED " << c.reduce() << endl;
    cout << "----------------------------------------" << endl;
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
            CurveElement tmp = x.new_mult(v->c_values.at(i));
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
        std::cout << "Updated tmp: " << toAssert << std::endl;
    }
    std::cout << "res is: " << toAssert << std::endl;
    std::cout << "challenge_prime: "  << challenge_prime << std::endl;
    std::cout << " challenge_prime_reduce: "  << challenge_prime_reduce << std::endl;
    assert(challenge_prime_reduce.operator==(toAssert));

    return true;
}

sign_values j(int n, CurveElement x,CurveElement P, CurveElement I){
    sign_values v;
    v.x = x;
    v.P = P;
    v.I = I;
    bool eval = true;
    
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
    v.eval = eval;
    
    return v;
}

void sign(CurveElement sk, CurveElement pk, CurveElement I) {
    const int n = 6;
    int index = 3;
    CurveElement Ls [n] = {};
    CurveElement qs [n] = {};
    CurveElement ws [n] = {};
    CurveElement Rs [n] = {};
    CurveElement cs [n] = {};
    CurveElement L_prime [n] = {};
    CurveElement R_prime [n] = {};
    CurveElement Responses [n] = {};
    cout << "sk is " << sk << endl;
    for (int i = 0; i < n; i++) {
        qs[i] = CurveElement::random_scalar_element();
        ws[i] = CurveElement::random_scalar_element();
        
        CurveElement tmp = pk;
        octetStream stream = tmp.hash(crypto_core_ristretto255_HASHBYTES);
        tmp.pack(stream);
        tmp.unpack(stream);
        
        CurveElement qG = qs[i].new_mult(generator); //CurveElement::base_mult(qs[i]);
        CurveElement qHP = tmp.new_mult(qs[i]);
        cout << "qhp is " << qHP << endl;
        cout << "ws[i] is " << ws[i] << endl;
        cout << "tmp is " << tmp << endl;
        cout << "pk is " << pk << endl;
        cout << "I is " << I << endl;

        if(index == i) { 
            Ls[i] = qG;
            Rs[i] = qHP;
        } else {
            //cout << "pk is " << pk << " and w[i] is " << ws[i] << endl;
            //cout << "I is " << I << " and w[i] is " << ws[i] << endl;
            Ls[i] = qG.new_add(pk.new_mult(ws[i]));
            cout << "Ls[i] is " << Ls[i] << endl;
            Rs[i] = qHP.new_add(I.new_mult(ws[i]));
            cout << "Rs[i] is " << Rs[i] << endl;
               
        }
    }

    unsigned char out[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);

    for(int i = 0; i < n*2; i++){
        if (i < n){
            crypto_hash_sha512_update(&state, Ls[i].get(), sizeof(Ls[i]));
        } else {
            crypto_hash_sha512_update(&state, Rs[i - n].get(), sizeof(Rs[i - n]));
        }       
    }
    crypto_hash_sha512_final(&state, out);
    
    CurveElement challenge = CurveElement::test(out);
    cout << "challenge is " << challenge << endl;


    for(int i = 0; i < n; i++) { 
        if (i == index) {
            CurveElement tmp;
            cout << "tmp is " << tmp << endl;
            
            for(int j = 0; j < n; j++) {
                if(j != index) {
                    cout << "challenge løkke " << endl;
                    cout << "ws[j] is " << ws[j] << endl;
                    cout << tmp.new_add(ws[j]) << endl;
                    tmp = tmp.new_add(ws[j]);
                }
            }
            cs[i] = challenge.new_sub(tmp);
        } else {
            cs[i] = ws[i];
        }
    }



    for (int i = 0; i < n; i++) {
        if(index != i) { 
            Responses[i] = qs[i];
        } else {
            cout << "sk " << sk << endl;
            cout << i << endl;
            CurveElement ggggg = cs[i].new_mult(sk);
            Responses[i] = qs[i].new_sub(ggggg); //qs[i].new_sub(cs[i].new_mult(sk));
            cout << "responses[i] is " << Responses[i] << endl;
            cout << qs[i].new_sub(ggggg) << endl;
        }
    }

    for(int i = 0; i < n; i++) {
        cout << i << endl;
        cout << "ws[i] "  << ws[i] << endl;
        cout << "cs[i] "  << cs[i] << endl;
    }

    for(int i = 0; i < n; i++){
        CurveElement rG = Responses[i].new_mult(generator); //CurveElement::base_mult(Responses[i]);
        CurveElement cP = pk.new_mult(cs[i]);
        L_prime[i] = rG.new_add(cP);

    
        CurveElement tmp = pk;
        octetStream stream = tmp.hash(crypto_core_ristretto255_HASHBYTES);
        tmp.pack(stream);
        tmp.unpack(stream);

        CurveElement rH = tmp.new_mult(Responses[i]);
        CurveElement cI = I.new_mult(cs[i]);
        R_prime[i] = rH.new_add(cI);

        std::cout << "Value of prime: " << L_prime[i] << " == " << Ls[i] << " is L" << std::endl;
        std::cout << L_prime[i].operator==(Ls[i]) << std::endl;
    }

    for (int i = 0; i <n; i++) {
        std::cout << "Value of prime: " << R_prime[i] << " == " << Rs[i] << " is R" << std::endl;
        std::cout << R_prime[i].operator==(Rs[i]) << std::endl;
    }

    unsigned char out_prime[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state_prime;
    crypto_hash_sha512_init(&state_prime);

    for(int i = 0; i < n*2; i++){
        if (i < n){
            cout << Ls[i] << " " << L_prime[i].operator==(Ls[i]) << " " << L_prime[i] << endl;
            crypto_hash_sha512_update(&state_prime, L_prime[i].get(), sizeof(L_prime[i]));
        } else {
            cout << Rs[i - n] << " " << R_prime[i - n].operator==(Rs[i - n]) << " " << R_prime[i - n] << endl;
            crypto_hash_sha512_update(&state_prime, R_prime[i - n].get(), sizeof(R_prime[i - n]));
        }       
    }
    crypto_hash_sha512_final(&state_prime, out_prime);

    CurveElement to_assert;
    std::cout << "initial value: " << to_assert << std::endl;
    for(int i = 0; i < n; i++){
        to_assert = to_assert.new_add(cs[i]);
        std::cout << "Updated tmp: " << to_assert << std::endl;
    }
    

    CurveElement challenge_prime =  CurveElement::test(out_prime);
    CurveElement challenge_prime_reduce = challenge_prime.reduce();
    cout << "challenge_prime is  " << challenge_prime <<  endl;
    cout << "challenge_prime is hash reduce " << challenge_prime_reduce <<  endl;
    cout << "challenge is hash " << challenge << endl;
    cout << "challenge is hash reduce " << challenge.reduce() << endl;
    cout << "challenge is sum c " << to_assert << endl;
    cout << challenge_prime_reduce.operator==(to_assert) << endl;

}


int main() {
    CurveElement::init();
    auto keypair = gen();
    sign(get<0>(keypair), get<1>(keypair), get<2>(keypair));


    sign_values v = j(n,get<0>(keypair), get<1>(keypair), get<2>(keypair));
    v = j(n,get<0>(keypair), get<1>(keypair), get<2>(keypair));
    
    split_c(&v);

    set_r_values(get<0>(keypair), &v);
    bool verifies = verify(&v);
    assert(verifies);

    //cout << get<0>(keypair) << " " << get<1>(keypair) << " " << get<2>(keypair) << endl;
    

   
    //std::cout << c2.Scalar() << std::endl;

    std::cout << "hejhej";
    return 0;
}