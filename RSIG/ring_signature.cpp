#include "ECDSA/CurveElement.h"
#include <iostream>
#include <tuple>
#include <typeinfo>
#include <stdlib.h>


#include "Tools/random.h"
#include "Math/gfp.h"
int n = 4;

CurveElement G = CurveElement::get_random_element();
struct sign_values{
    bool eval;
    CurveElement I;
    CurveElement x;
    CurveElement P;
    CurveElement L_prime[4];
    CurveElement R_prime[4];
    CurveElement q_values[4];
    CurveElement w_values[4];
    CurveElement L_values[4];
    CurveElement R_values[4];
    CurveElement c_values[4];
    CurveElement r_values[4];
};

struct signature{
    CurveElement I;
    CurveElement c_values[4];
    CurveElement r_values[4];
};

bigint l = (bigint(1) << 252) + bigint("27742317777372353535851937790883648493"); 

ostream& operator <<(ostream& s, const unsigned char* x) {
    s << hex << *(word*)x;
    return s;
}

template<typename T>
void get_type(T variable){
    std::cout << "The type of: " << variable << " is: " << typeid(variable).name() << endl;
}

CurveElement get_hash(CurveElement to_hash){
    CurveElement I = to_hash;
    octetStream os = I.hash(64);
    I.pack(os);
    I.unpack(os);
    I.check();
    return I;
}
CurveElement compute_challenge(int n, sign_values* v, bool verifying = false){
    unsigned char out[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    if (!verifying) { 
        for(int i = 0; i < n*2; i++){
            if (i < n){
                crypto_hash_sha512_update(&state, v->L_values[i].get(), sizeof v->L_values[i].get());
            } else {
                crypto_hash_sha512_update(&state, v->R_values[i-n].get(), sizeof v->R_values[i-n].get());
            }
        }
    } else {
        for(int i = 0; i < n*2; i++){
            std::cout << "asdjaslkdjaslædkaj" << std::endl;
            if (i < n){
                crypto_hash_sha512_update(&state, v->L_prime[i].get(), sizeof v->L_prime[i].get());
            } else {
                crypto_hash_sha512_update(&state, v->R_prime[i-n].get(), sizeof v->R_prime[i-n].get());
            }
        }
    }
    crypto_hash_sha512_final(&state, out);
    std::cout << "The hash is currently: " << out << std::endl;
    CurveElement res = CurveElement::hash_to_elem(out);
    return res;
}
std::tuple<CurveElement, CurveElement, CurveElement> gen(CurveElement opt_sk){
    CurveElement x = NULL;
    CurveElement P = NULL;
    if (opt_sk == NULL){
        x.make_random_element();
        P = x.multi(G); //mult_by_base();
    } else {
        x = opt_sk;
        P = x.multi(G); // mult_by_base();
    }
    
    CurveElement h = get_hash(P);
    CurveElement I = x.multi(h);
    std::cout << "THE HASH IS: " << h << std::endl;
    std::cout << "Secret x: " << x << std::endl;
    std::cout << "Public Key P: " << P << std::endl;
    std::cout << "Key Image I:" << I << std::endl;

    return std::make_tuple(x,P,I);
}
//std::tuple<unsigned char, unsigned char> sampler(int n){
//std::tuple<bool, unsigned char, unsigned char, unsigned char, unsigned char>j(int n, CurveElement x,CurveElement P, CurveElement I){

void split_c(sign_values* v){
    CurveElement c = compute_challenge(n, v);
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "The challenge is found to be: NOT REDUCED" << c << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    for(int i = 0; i < n; i++ ){
        if(i == 3){
            CurveElement tmp;
            for(int j = 0; j < n; j++){     
                if(j != 3){
                    tmp = tmp.operator+(v->w_values[j]);
                }
            }
            CurveElement res = c.operator-(tmp);
            v->c_values[i] = res; // tmp.operator-(v->w_values[i]);
        } else {
            v->c_values[i] = v->w_values[i];
        }
    }
    for(int i = 0; i < n; i++){
        std::cout << "c" << i << ": " << v->c_values[i] << std::endl;
    }
}


sign_values j(int n, CurveElement x,CurveElement P, CurveElement I){

    sign_values v;
    v.x = x;
    v.P = P;
    v.I = I;
    for (int i = 0; i < n; i++){
        CurveElement q;
        CurveElement w;
        q.make_random_element();
        w.make_random_element();
        v.q_values[i] = q;
        v.w_values[i] = w;
    }

    bool eval = true;
    for(int i = 0; i < n; i++){
        CurveElement L;
        CurveElement R;
        CurveElement qG = v.q_values[i].multi(G);//mult_by_base(); 
        CurveElement h = get_hash(P);
        CurveElement qH = v.q_values[i].multi(h);
        if (qH == 0){ eval = false;}
        if (i == 3) {
            v.L_values[i] = qG;           
            v.R_values[i] = qH;
            continue;
        }
        CurveElement wP = v.w_values[i].multi(P);
        v.L_values[i] = qG.operator+(wP);
        CurveElement wI = v.w_values[i].multi(I);
        v.R_values[i] = qH.operator+(wI);
    }
    v.eval = eval;
    return v;
}

void set_r_values(CurveElement x, sign_values* v){
    for(int i = 0; i < n; i++){
        if(i == 3){
            CurveElement tmp = x.multi(v->c_values[i]);
            v->r_values[i] = v->q_values[i].operator-(tmp); 
            continue;
        }
        v->r_values[i] = v->q_values[i];
    }
}

bool verify(sign_values* v){
    //CurveElement L_prime[n];
    //CurveElement R_prime[n];   
    for(int i = 0; i < n; i++){
        CurveElement L_tmp0 = v->r_values[i].multi(G);//mult_by_base();
        CurveElement L_tmp1 = v->c_values[i].multi(v->P);
        v->L_prime[i] = L_tmp0.operator+(L_tmp1);
        
        CurveElement hP = get_hash(v->P);
        CurveElement rHp = v->r_values[i].multi(hP);
        CurveElement cI = v->c_values[i].multi(v->I);
        v->R_prime[i] = rHp.operator+(cI);
        assert(v->L_values[i].operator==(v->L_prime[i])); 
        std::cout << "We are at index i = " << i << std::endl;
        std::cout << "Value of L_prime: " << v->L_prime[i] << " == " << v->L_values[i] << " is L" << std::endl;
        std::cout << "Value of R_prime: " << v->R_prime[i] << " == " << v->R_values[i] << " is R" << std::endl;
        std::cout << "RPRIME == R?: " << v->R_prime[i].operator==(v->R_values[i]) << std::endl;
        std::cout << "LPRIME == L?: " << v->L_prime[i].operator==(v->L_values[i]) << std::endl;
    }
    CurveElement c_verf_padded = compute_challenge(n, v, true);
    CurveElement c_verf = c_verf_padded.reduce();
    /*std::cout << "------------------------------------------" << std::endl;
    std::cout << "unpadded: " << c_padded << "=?=" << c_verf_padded << std::endl;
    std::cout << "------------------------------------------" << std::endl;*/
    CurveElement toAssert;
    std::cout << "SUMMING THE C_VALUES" << std::endl;
    for(int i = 0; i < n; i++){
        std::cout << toAssert <<"+" <<v->c_values[i] << std::endl;
        toAssert = toAssert.operator+(v->c_values[i]);
        std::cout << "equals: " << toAssert << std::endl;
    }
    std::cout << "res is: " << toAssert << std::endl;
    std::cout << "c_verf_padded: "  << c_verf_padded << std::endl;
    std::cout << "c_verf_padded after reduce: "  << c_verf << std::endl;
    std::cout << "padded " << c_verf_padded << "==" << toAssert << std::endl;
    std::cout << "unpadded " << c_verf << "==" << toAssert << std::endl;
    assert(c_verf.operator==(toAssert));

    return true;
}

int main(){
    CurveElement x;
    CurveElement P;
    CurveElement I;
    tie(x,P,I) = gen(NULL);
    
    sign_values v = j(n,x,P,I);
  
    v = j(n,x,P,I);
    
    split_c(&v);

    set_r_values(x, &v);
    
    bool verifies = verify(&v);
    assert(verifies);
}



/*
 *https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function
 * https://doc.libsodium.org/advanced/point-arithmetic/ristretto#hash-to-group
 * https://bytecoin.org/old/whitepaper.pdf
 */
