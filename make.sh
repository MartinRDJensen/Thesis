#!/bin/bash
alias build='../MP-SPDZ/Fake-RSIG.x'
alias run='./run_fake_parties.sh';
alias mk='cp RSIG/* ../MP-SPDZ/RSIG/; cp fake-stuff.hpp ../MP-SPDZ/Protocols; cp Makefile ../MP-SPDZ; make rsig -C ../MP-SPDZ/';

