#include "ECDSA/CurveElement.h"
#include <iostream>
#include <tuple>
#include <typeinfo>
#include <stdlib.h>


#include "Tools/random.h"
#include "Math/gfp.h"

struct sign_values{
    bool eval;
    CurveElement q_values[4];
    CurveElement w_values[4];
    CurveElement L_values[4];
    CurveElement R_values[4];
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
    std::cout << "in hash: "<<I << std::endl;
    octetStream os = I.hash(32);
    I.pack(os);
    I.unpack(os);
    I.check();
    std::cout << "in hash: "<<I << std::endl;

    return I;
}
CurveElement compute_challenge(int n, sign_values v){
    unsigned char out[crypto_hash_sha512_BYTES]; 
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);

    for(int i = 0; i < n*2; i++){
        if (i > n){
            crypto_hash_sha512_update(&state, v.L_values[i].get(), sizeof v.L_values[i].get());
        }
            crypto_hash_sha512_update(&state, v.R_values[i].get(), sizeof v.R_values[i].get());
    }
    
    crypto_hash_sha512_final(&state, out);
    CurveElement res = CurveElement::hash_to_elem(out);
    return res;
}
std::tuple<CurveElement, CurveElement, CurveElement> gen(CurveElement opt_sk){
    CurveElement x = NULL;
    CurveElement P = NULL;
    if (opt_sk == NULL){
        x.make_random_element();
        P = x.mult_by_base();
    } else {
        x = opt_sk;
        P = x.mult_by_base();
    }
     
    unsigned char hash[crypto_generichash_BYTES];
    int v = crypto_generichash(hash, sizeof hash, P.get(), sizeof P.get(), NULL, 0);

    CurveElement I = P;
    std::cout << "I: "  << I << " P: " << P << std::endl;
    octetStream oss = I.hash(32);
    I.pack(oss);
    I.unpack(oss);
    std::cout << "I: "  << I << " P: " << P << std::endl;

    //I.set_a(hash); 
    
    std::cout << hash << "   " << std::endl;
    std::cout << v << std::endl;
    std::cout << "Secret x: " << x << std::endl;
    std::cout << "Public Key P: " << P << std::endl;
    std::cout << "Key Image I:" << I << std::endl;

    get_type(x);
    get_type(P);
    get_type(I);
    return std::make_tuple(x,P,I);
}
//std::tuple<unsigned char, unsigned char> sampler(int n){
//std::tuple<bool, unsigned char, unsigned char, unsigned char, unsigned char>j(int n, CurveElement x,CurveElement P, CurveElement I){
sign_values j(int n, CurveElement x,CurveElement P, CurveElement I){

    sign_values v;
    std::cout << "secret x: " << x << std::endl;
    /*CurveElement q_values[n];
    CurveElement w_values[n];
    CurveElement L_values[n];
    CurveElement R_values[n];*/
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
        CurveElement qG = v.q_values[i].mult_by_base(); 
        CurveElement h = get_hash(P);
        CurveElement qH = v.q_values[i].multi(h);
        if (qH == 0){ eval = false;}
        std::cout << "qG: "<< qG << ", H(P): " << h << ", qH: " << qH << std::endl;
        if (i == 3) {
            v.L_values[i] = qG;           
            v.R_values[i] = qH;
            continue;
        }
        CurveElement wP = v.w_values[i].multi(P);
        std::cout << "wP: "<< wP << std::endl;
        //L_values[i] = qG.operator+(wP);
        v.L_values[i] = qG.operator+(wP);
        CurveElement wI = v.w_values[i].multi(I);
        //R_values[i] = qH.operator+(wI);
        v.R_values[i] = qH.operator+(wI);
        std::cout << "qH+wP: "<< v.L_values[i] << std::endl;
        std::cout << "qH+wI: "<< v.R_values[i] << std::endl;
    }
    for(int i = 0; i < n; i++){
        std::cout << "L: " << v.L_values[i] << ", R: " << v.R_values[i] << std::endl;
    }
    /*
    v.q_values = q_values;
    v.w_values = w_values;
    v.L_values = L_values;
    v.R_values = R_values;*/
    v.eval = eval;
    return v;
//    return std::make_tuple(eval, q_values, w_values, L_values, R_values);
}

int main(){
    std::cout << "----------------------------------------" << std::endl;
    CurveElement::init();
    CurveElement x;
    CurveElement P;
    CurveElement I;
    CurveElement q_values[4];
    CurveElement w_values[4];
    CurveElement L_values[4];
    CurveElement R_values[4];
    bool test = false;

    tie(x,P,I) = gen(NULL);
    //tie(test, q_values, w_values, L_values, R_values) = j(4,x,P,I);
    sign_values v = j(4,x,P,I);
    while (!test){
        tie(x,P,I) = gen(NULL);
        v = j(4,x,P,I);
        test = v.eval;
    }
    CurveElement c = compute_challenge(4, v);
    CurveElement tmp;
    tmp = c.operator-(v.w_values[0]);
    for(int i = 1; i < 4; i++ ){
        std::cout << "c: " << tmp << std::endl;
        if(i != 3){
            tmp = tmp.operator-(v.w_values[i]);
        }
    }
    std::cout << "c: " << c << std::endl;
    std::cout << "----------------------------------------" << std::endl;


    CurveElement c1(200);
    CurveElement c2(100);
    CurveElement res = c2.operator+(c1);
    std::cout << c1 << std::endl;
    std::cout << c2 << std::endl;
    std::cout << res << std::endl;
    std::cout << "---------------------------------------" << std::endl;
    std::cout << c1 << std::endl;
    c1.make_random_element();
    std::cout << c1 << std::endl;
}
