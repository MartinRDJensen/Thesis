#include <iostream>
#include "ECDSA/P256Element.h"
#include "Math/gfp.hpp"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

/*
EC_GROUP* P256Element::curve;

void P256Element::init()
{
    std::cout << NID_X9_62_prime256v1 << std::endl;
    curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    assert(curve != 0);
    auto modulus = EC_GROUP_get0_order(curve);
    Scalar::init_field(BN_bn2dec(modulus), false);
}
*/

int main(){
    P256Element::init();
    std::cout << "Hello";
}
