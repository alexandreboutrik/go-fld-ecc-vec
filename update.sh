#!/bin/bash

function apply_patch() {
    sed -i "s,static inline void randEd25519_Key,extern void randEd25519_Key,g" src/sign255.c
    sed -i "s,static inline void printEd25519_Key,extern void printEd25519_Key,g" src/sign255.c
    sed -i "s,static int ed25519_keygen,extern int ed25519_keygen,g" src/sign255.c
    sed -i "s,static int ed25519_sign,extern int ed25519_sign,g" src/sign255.c
    sed -i "s,static int ed25519_verify,extern int ed25519_verify,g" src/sign255.c
}

function compile_eddsa_avx() {
    if [ ! -d "./fld-ecc-vec" ] ; then
        git clone https://github.com/armfazh/fld-ecc-vec
    fi

    cd fld-ecc-vec
    apply_patch
    mkdir build; cd build
    cmake .. ||
    { echo "Failed to compile fld-ecc-vec. Cmake. Exiting" ; exit 1 ;}
    time make all ||
    { echo "Failed to compile fld-ecc-vec. Make. Exiting" ; exit 1 ;}
    cd ..; cd ..
}

function copy_libs() {
    mkdir -p ./build
    cp -v ./fld-ecc-vec/build/lib/* ./build/
}

compile_eddsa_avx
copy_libs

rm -rf ./fld-ecc-vec
