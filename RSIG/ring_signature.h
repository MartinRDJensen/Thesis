#include "ECDSA/CurveElement.h"
#include <tuple>

struct sign_values;

CurveElement get_hash(CurveElement to_hash);
CurveElement::Scalar hash_to_scalar(const unsigned char* hash);
std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen();
CurveElement::Scalar compute_challenge(int n, sign_values* values, bool verifying);
void split_c(sign_values* values);
void set_r_values(sign_values* values);
bool verify(sign_values* values);
sign_values j(int n, CurveElement::Scalar x, CurveElement P, CurveElement I);

