#include "CurveElement.h"
#include "Math/gfp.hpp"
#include <vector>
class eqbox{
public:
  vector<CurveElement::Scalar> shares_of_one;
  vector<vector<CurveElement::Scalar>> zero_share;
};


eqbox eq_box;

std::vector<CurveElement::Scalar> genShares2(int n, CurveElement::Scalar value){
  std::vector<CurveElement::Scalar> shares;
  for(int i = 0; i < n; i++){
    auto tmp = SeededPRNG().get<CurveElement::Scalar>();
    if(i == n-1){
      CurveElement::Scalar res = value;
      for(CurveElement::Scalar var : shares){
        res = res - var;
      }
      shares.push_back(res);
    } else { shares.push_back(tmp); }
  }
  return shares;
}



CurveElement::Scalar eq_testing(int position, int index) {
  if(position == 0) {
     if(index != 0) {
        CurveElement::Scalar zero;
        vector<CurveElement::Scalar> zero_share = genShares2(10, zero);
        eq_box.zero_share.push_back(zero_share);
  } else {
    CurveElement::Scalar one = 1;
    eq_box.shares_of_one = genShares2(10, one);
  }
  }
    if(index != 0) {
      return eq_box.zero_share.at(index - 1).at(position);
    }
    return eq_box.shares_of_one.at(position);

}
