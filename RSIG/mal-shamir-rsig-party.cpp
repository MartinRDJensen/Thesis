#include "Protocols/MaliciousShamirShare.h"

#include "Protocols/Shamir.hpp"
#include "Protocols/ShamirInput.hpp"

#include "hm-rsig-shamir-party.hpp"

int main(int argc, const char** argv)
{
  ez::ezOptionParser opt;
  ShamirOptions(opt, argc, argv);
  run<MaliciousShamirShare>(argc, argv);
}
