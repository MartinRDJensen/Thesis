#!/bin/bash
alias clean='cd ../MP-SPDZ/; make clean; cd ../Thesis/'
alias mk='cp RSIG/* ../MP-SPDZ/RSIG/; cp fake-stuff.hpp ../MP-SPDZ/Protocols; cp Data_Files.h ../MP-SPDZ/Processor ;cp MascotPrep.* ../MP-SPDZ/Protocols; cp Makefile ../MP-SPDZ; make -j8 rsig -C ../MP-SPDZ/';

