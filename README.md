# Thesis
CryptoNote white paper over MPC

# How to compile
Have the MP-SPDZ library and this git repository in same folder i.e a folde structure like the following:
```
                   ---- MP-SPDZ
top-level-folder --|
                   ---- Thesis
```

To make things easier in the Thesis folder run the command "source ./make.sh".
This sets up aliases that we have used throughout the project. The most relevanvt being 'mk' and it should only be executed when in the Thesis folder.
If you write the command "mk" it runs the makefile, we have in Thesis, in the MP-SPDZ folder.
However, before you run "mk" a directory called RSIG in MP-SPDZ should be created as well.

After compiling with "mk" there will be various files with the naming "*-rsig-party.x" in the MP-SPDZ directory.
To run these use the following syntax:

```
Shell 1:
./*-rsig-party.x -p 0

Shell 2:
./*-rsig-party.x -p 0
```
where * is to be understood as a wildcard to be filled in.

Specifically to run fake-spdz-rsig-party you will have to create a Player-Data directory in MP-SPDZ and thereafter run Fake-RSIG.x which will create local preprocesing data for the two parties.


# Notes
By default the executables will run 1000 iterations. The variable that sets this is the buffer_size variable in the setup files. To easily see the places where to change it use grep -r "buffer_size" in the Thesis directroy.

The commit that we have been working with for the MP-SPDZ library is "88534961b3492b7804f2de0d8425f5ee0b401bdb". To get to this commit one can simply do:
```
git clone https://github.com/data61/MP-SPDZ.git
git checkout 88534961b3492b7804f2de0d8425f5ee0b401bdb
```
