#include "CurveElement.h"
#include <tuple>

struct sign_values{
    CurveElement I;
    CurveElement x;
    std::vector<CurveElement> P;
    CurveElement hP;
    std::vector<CurveElement> L_prime;
    std::vector<CurveElement> R_prime;
    std::vector<CurveElement::Scalar> q_values;
    std::vector<CurveElement::Scalar> w_values;
    std::vector<CurveElement> L_values;
    std::vector<CurveElement> R_values;
    std::vector<CurveElement::Scalar> c_values;
    std::vector<CurveElement::Scalar> r_values;
    unsigned char* m;
};

CurveElement get_hash(CurveElement to_hash);
CurveElement::Scalar hash_to_scalar(const unsigned char* hash);
std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen();
CurveElement::Scalar compute_challenge(sign_values* values, bool verifying);
void split_c(sign_values* values);
void set_r_values(CurveElement::Scalar x,sign_values* values);
bool verify(sign_values* values);
sign_values j(unsigned char* m, CurveElement::Scalar x, vector<CurveElement> P, CurveElement I);

