#include "CurveElement.h"
#include "RSIGOptions.h"
#include "Processor/Data_Files.h"
#include "Protocols/ReplicatedPrep.h"
#include "Protocols/MaliciousShamirShare.h"
#include "Protocols/Rep3Share.h"
#include "GC/TinierSecret.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/TinyMC.h"
#include "GC/TinierSharePrep.hpp"
#include "GC/CcdSecret.h"

template<template<class U> class T>
class RSIGTuple{
public:
  T<CurveElement::Scalar> secret_L;
  T<CurveElement::Scalar> secret_R;
  T<CurveElement::Scalar> secret_challenges;
  T<CurveElement::Scalar> secret_responses;
};
/*
a,b,c is mult triple ; not sure if shares
secret R =>?
R => ?
R => probably kG
      T<P256Element::Scalar> a;
    T<P256Element::Scalar> b;
    P256Element::Scalar c;
    T<P256Element> secret_R;
    P256Element R;
};
*/
