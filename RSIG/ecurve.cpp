#include <iostream>
#include "ECDSA/P256Element.h"
#include "Math/gfp.hpp"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <assert.h>
#include "ecurve.h"

#include <typeinfo>

EC_GROUP* ECurve::curve;
const EC_POINT* ECurve::G;

void ECurve::init(){
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    assert(curve != 0);
    auto modulus = EC_GROUP_get0_order(curve);
    std::cout << "Modulus is: " << modulus << std::endl;
    std::cout << "type is: " << typeid(modulus).name() << std::endl;
    Scalar::init_field(BN_bn2dec(modulus), false);
}

void ECurve::get_generator(){ 
    G = EC_GROUP_get0_generator(curve);
    std::cout << "Gtype is: " << typeid(G).name() << std::endl;
    std::cout << "gen is: " << G << std::endl;
}
EC_POINT* ECurve::addition(EC_POINT *p1, EC_POINT *p2){
    EC_POINT* res = EC_POINT_new(curve);
    assert(res != 0);
    assert(EC_POINT_set_to_infinity(curve, res) != 0);
    int issues = EC_POINT_add(curve, res, p1, p2, 0);
    assert(issues != 0);
    return res;
}

EC_POINT* ECurve::gen_point(){
    EC_POINT* p = EC_POINT_new(curve);
    assert(p != 0);
    assert(EC_POINT_is_at_infinity(curve, p) != 0);
    return p;
}

std::tuple<BIGNUM*, BIGNUM*> ECurve::get_coordinates(EC_POINT* p){
    BIGNUM* y = NULL;
    BIGNUM* x = NULL;
    int ppl = EC_POINT_get_affine_coordinates(curve, p, x, y, 0);
    std::cout << "ppl: " << ppl <<  std::endl;
   // assert(EC_POINT_get_affine_coordinates(curve, p, x, 0, 0) != 0);
    return std::make_tuple(x,y); 
}

int main(){
    ECurve::init();
    std::cout << "Type: " << ECurve::curve_type() << std::endl; 
    //P256Element::init();
    //ECurve c;
    ECurve::get_generator();

    EC_POINT* p1 = ECurve::gen_point();
    EC_POINT* p2 = ECurve::gen_point();
    EC_POINT* tmp = ECurve::addition(p1, p2);
    BIGNUM* b; 
    BIGNUM* a; 
    tie(a, b) = ECurve::get_coordinates(p1);
    std::cout << "v1: " << a <<  " v2: " << b << std::endl;
    std::cout << "p1: " << p1<< std::endl;
    std::cout << "p2: " << p2<< std::endl;
    std::cout << "res: " << tmp<< std::endl;
    std::cout << "Hello";
}
