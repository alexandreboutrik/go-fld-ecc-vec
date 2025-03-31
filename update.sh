#!/bin/bash

function apply_patch() {
    sed -i "s,static inline void randEd25519_Key,extern void randEd25519_Key,g" src/sign255.c
    sed -i "s,static inline void printEd25519_Key,extern void printEd25519_Key,g" src/sign255.c
    sed -i "s,static int ed25519_keygen,extern int ed25519_keygen,g" src/sign255.c
    sed -i "s,static int ed25519_sign,extern int ed25519_sign,g" src/sign255.c
    sed -i "s,static int ed25519_verify,extern int ed25519_verify,g" src/sign255.c
}

git clone https://github.com/armfazh/fld-ecc-vec
cd fld-ecc-vec
apply_patch
mkdir build; cd build
cmake ..
time make all
cd lib
sudo cp ./* /usr/local/lib
