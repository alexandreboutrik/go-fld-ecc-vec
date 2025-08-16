package eddsa_avx2

import (
	"unsafe"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

/*

#cgo LDFLAGS: -L/usr/local/lib
#cgo LDFLAGS: -L ${SRCDIR}/build
#cgo LDFLAGS: -l:libfaz_ecc_avx2.a

#include "faz_eddsa_avx2.h"

#include <stdlib.h>
#include <stdint.h>

extern void randEd25519_Key(argEdDSA_PrivateKey key);
extern int ed25519_keygen(argEdDSA_PublicKey public_key, const argEdDSA_PrivateKey private_key);

extern int ed25519_sign(argEdDSA_Signature signature, const uint8_t *message, uint64_t message_length, const argEdDSA_PublicKey public_key, const argEdDSA_PrivateKey private_key);

extern int ed25519_verify(const uint8_t *message, uint64_t message_length, const argEdDSA_PublicKey public_key, const argEdDSA_Signature signature);

extern void printEd25519_Key(FILE * file,argEdDSA_PrivateKey key);
extern void printEd25519_Signature(FILE * file,uint8_t *sig);

*/
import "C"

type PublicKey struct {
	CPublicKey *C.uint8_t
}

type PrivateKey struct {
	CSecretKey *C.uint8_t
}

var public_key *PublicKey
var private_key *PrivateKey

func randkey(sk *C.uint8_t) {
	C.randEd25519_Key(sk)
}

func PublicKeyFromBytes(data []byte) (*PublicKey, error) {
	if len(data) != C.ED25519_KEY_SIZE_BYTES_PARAM {
		return nil, fmt.Errorf("eddsa_avx: invalid key size")
	}

	cPubKeyPtr := C.CBytes(data)
	if cPubKeyPtr == nil {
		return nil, fmt.Errorf("eddsa_avx: failed to allocate memory")
	}

	publicKey := &PublicKey{CPublicKey: (*C.uchar)(cPubKeyPtr)}

	runtime.SetFinalizer(publicKey, func(pk *PublicKey) {
		C.free(unsafe.Pointer(pk.CPublicKey))
	})

	return publicKey, nil
}

func (pub *PublicKey) Bytes() []byte {
	if pub.CPublicKey == nil {
		return nil
	}

	return C.GoBytes(unsafe.Pointer(pub.CPublicKey), C.int(C.ED25519_KEY_SIZE_BYTES_PARAM))
}

func (priv *PrivateKey) Bytes() []byte {
	if priv.CSecretKey == nil {
		return nil
	}

	return C.GoBytes(unsafe.Pointer(priv.CSecretKey), C.int(C.ED25519_KEY_SIZE_BYTES_PARAM))
}

func Keygen() (pub *PublicKey, priv *PrivateKey, err error) {
	pk := (*C.uint8_t)(unsafe.Pointer(C.CString(strings.Repeat("0", C.ED25519_KEY_SIZE_BYTES_PARAM))))
	sk := (*C.uint8_t)(unsafe.Pointer(C.CString(strings.Repeat("0", C.ED25519_KEY_SIZE_BYTES_PARAM))))

	randkey(sk)

	ret := C.ed25519_keygen(pk, sk)
	if ret != C.EDDSA_KEYGEN_OK {
		return nil, nil, errors.New("eddsa_avx: Keygen failed.")
	}

	public_key = &PublicKey{CPublicKey: pk}
	private_key = &PrivateKey{CSecretKey: sk}

	return public_key, private_key, nil
}

func Sign(message []byte, pub *PublicKey, priv *PrivateKey) (signature []byte, err error) {
	sm := C.CString(strings.Repeat("0", C.ED25519_SIG_SIZE_BYTES_PARAM))
	defer C.free(unsafe.Pointer(sm))

	ret := C.ed25519_sign(
		(*C.uint8_t)(unsafe.Pointer(sm)),
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		(C.uint64_t)(len(message)),
		(*C.uint8_t)(unsafe.Pointer(pub.CPublicKey)),
		(*C.uint8_t)(unsafe.Pointer(priv.CSecretKey)))
	if ret != C.EDDSA_SIGNATURE_OK {
		return nil, errors.New("eddsa_avx: Sign failed.")
	}

	signature = C.GoBytes((unsafe.Pointer(sm)), (C.int)(C.ED25519_SIG_SIZE_BYTES_PARAM))

	return signature, nil
}

func Verify(message []byte, pub *PublicKey, signature []byte) (valid bool) {
	sm := C.CString(string(signature))
	defer C.free(unsafe.Pointer(sm))

	ret := C.ed25519_verify(
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		(C.uint64_t)(len(message)),
		(*C.uint8_t)(unsafe.Pointer(pub.CPublicKey)),
		(*C.uint8_t)(unsafe.Pointer(sm)))
	return (ret == C.EDDSA_VERIFICATION_OK)
}

func Printkey(key interface{}) {
	switch k := key.(type) {
	// It needs to have separate cases for each type because the case
	// statement performs a type assertion
	case *C.uint8_t:
		C.printEd25519_Key(
			C.stdout, k)
	case *PublicKey:
		C.printEd25519_Key(
			C.stdout,
       		(*C.uint8_t)(unsafe.Pointer(k)))
	case *PrivateKey:
		C.printEd25519_Key(
			C.stdout,
       		(*C.uint8_t)(unsafe.Pointer(k)))
	}
}
