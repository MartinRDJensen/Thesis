#ifndef UTIL_H
#define UTIL_H

#include "CurveElement.h"

CurveElement::Scalar crypto_hash(unsigned char *m, std::vector<CurveElement> L, std::vector<CurveElement> R);

CurveElement::Scalar hash_to_scalar(const unsigned char* h);

std::tuple<CurveElement::Scalar, CurveElement, CurveElement> gen(CurveElement::Scalar skVal);

std::vector<CurveElement> genPublicKeys(int n, CurveElement pk);

struct bench_coll{
  int PRANDM;
  int EQ_TEST_ALL;
  int EQ_TEST_TRIPLE_CONSUME;
  int q_w_L_R;
  int buffer_size_sign = 0;
  int buffer_size_verf = 0;
  int total_online = 0;
  int verf_time = 0;
  int total_online_bytes = 0;
};

void print_timers(bench_coll* timer_struct, int buffer_size);
#endif /* UTIL_H */
