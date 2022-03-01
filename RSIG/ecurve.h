#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <tuple>
#include "Math/gfp.h"

class ECurve {
    public:
        typedef gfp_<2,4> Scalar;
    private:
        static EC_GROUP* curve;
        static const EC_POINT* G;
        EC_POINT* point;
    public:
        static string curve_type() { return "secp256k1";}
        static void init();
        ECurve();
        static EC_POINT* addition(EC_POINT *p1, EC_POINT *p2);
        static EC_POINT* gen_point();
        static int mult(int x);
        static void get_generator();
        static std::tuple<BIGNUM*, BIGNUM*>  get_coordinates(EC_POINT* p);

};
