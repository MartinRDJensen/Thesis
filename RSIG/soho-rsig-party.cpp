#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "GC/VectorInput.h"

//#include "Protocols/Share.hpp"
#include "Protocols/SohoShare.h"
#include "Protocols/SohoPrep.hpp"
#include "Protocols/MAC_Check.hpp"
#include "GC/Secret.hpp"
#include "GC/TinierSharePrep.hpp"
//#include "ot-ecdsa-party.hpp"
#include "soho-test.cpp"

#include <assert.h>

int main(int argc, const char** argv)
{
    run<SohoShare>(argc, argv);
}
