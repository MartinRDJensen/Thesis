#include "CurveElement.h"
#include "Tools/mkpath.h"
#include "GC/TinierSecret.h"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/Share.hpp"
#include "Processor/Data_Files.hpp"
#include "Math/gfp.hpp"

int main()
{
    CurveElement::init();
    CurveElement::Scalar key;
    string prefix = PREP_DIR "RSIG/";
    mkdir_p(prefix.c_str());
    write_online_setup(prefix, CurveElement::Scalar::pr());
    generate_mac_keys<Share<CurveElement::Scalar>>(key, 2, prefix);
    make_mult_triples<Share<CurveElement::Scalar>>(key, 2, 1000, false, prefix);
    make_inverse<Share<CurveElement::Scalar>>(key, 2, 1000, false, prefix);
    make_bit<Share<CurveElement::Scalar>>(key, 2, 1000, false, prefix);
}
