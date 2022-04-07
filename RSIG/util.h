#include "CurveElement.h"

CurveElement::Scalar crypto_hash(unsigned char *m, std::vector<CurveElement> L, std::vector<CurveElement> R);

CurveElement::Scalar hash_to_scalar(const unsigned char* h);

std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen(int skVal);

std::vector<CurveElement> genPublicKeys(int n, CurveElement pk);
