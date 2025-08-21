#!/bin/bash

function apply_patch() {
    sed -i "s,static inline void randEd25519_Key,extern void randEd25519_Key,g" src/sign255.c
    sed -i "s,static inline void printEd25519_Key,extern void printEd25519_Key,g" src/sign255.c
    sed -i "s,static int ed25519_keygen,extern int ed25519_keygen,g" src/sign255.c
    sed -i "s,static int ed25519_sign,extern int ed25519_sign,g" src/sign255.c
    sed -i "s,static int ed25519_verify,extern int ed25519_verify,g" src/sign255.c
}

function rename_obj() {
	mkdir tmp && cd tmp || exit 1

	ar x ../lib/libfaz_ecc_avx2.a || exit 1
	for file in *.o ; do
		objcopy --redefine-sym SHAKE128=faz_SHAKE128 \
				--redefine-sym SHAKE256=faz_SHAKE256 \
				"${file}"
	done

	ar rcs ../lib/libfaz_ecc_avx2.a *.o && cd .. || exit 1

	echo "Symbols renamed successfully."
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

	rename_obj

    cd ..; cd ..
}

function copy_libs() {
    mkdir -p ./build
    cp -v ./fld-ecc-vec/build/lib/* ./build/
}

compile_eddsa_avx
copy_libs

rm -rf ./fld-ecc-vec
