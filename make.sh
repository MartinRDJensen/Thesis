#!/bin/bash
alias run='cd ../MP-SPDZ/; ./RSIG.x; cd ../Thesis/';
alias mk='cp RSIG/* ../MP-SPDZ/RSIG/; mv fake-stuff.hpp ../MP-SPDZ/Protocols; mv Makefile ../MP-SPDZ; make rsig -C ../MP-SPDZ/';


