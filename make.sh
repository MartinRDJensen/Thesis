#!/bin/bash
alias build='cd ../MP-SPDZ/; ./Fake-RSIG.x; cd ../Thesis/'
alias clean='cd ../MP-SPDZ/; make clean; cd ../Thesis/'
alias run='./run_fake_parties.sh';
alias mk='cp RSIG/* ../MP-SPDZ/RSIG/; cp fake-stuff.hpp ../MP-SPDZ/Protocols; cp Makefile ../MP-SPDZ; make -j8 rsig -C ../MP-SPDZ/';

