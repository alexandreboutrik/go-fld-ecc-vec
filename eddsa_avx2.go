package eddsa_avx2

import (
	"crypto"
	"unsafe"
	"errors"
	"fmt"
	"io"
	"runtime"
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

var ED25519_KEY_SIZE_BYTES_PARAM int = C.ED25519_KEY_SIZE_BYTES_PARAM
var ED25519_SIG_SIZE_BYTES_PARAM int = C.ED25519_SIG_SIZE_BYTES_PARAM

type PublicKey struct {
	cPublicKey *C.uint8_t
}

type PrivateKey struct {
	cSecretKey *C.uint8_t
	publicKey *PublicKey
}

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

	publicKey := &PublicKey{cPublicKey: (*C.uchar)(cPubKeyPtr)}

	runtime.SetFinalizer(publicKey, func(pk *PublicKey) {
		C.free(unsafe.Pointer(pk.cPublicKey))
	})

	return publicKey, nil
}

func PrivateKeyFromBytes(data []byte) (*PrivateKey, error) {
	if len(data) != C.ED25519_KEY_SIZE_BYTES_PARAM {
		return nil, fmt.Errorf("eddsa_avx: invalid key size")
	}

	cSecKeyPtr := C.CBytes(data)
	if cSecKeyPtr == nil {
		return nil, fmt.Errorf("eddsa_avx: failed to allocate memory")
	}

	cPubKeyPtr := C.malloc(C.ED25519_KEY_SIZE_BYTES_PARAM)
	if cPubKeyPtr == nil {
		C.free(cSecKeyPtr)
		return nil, fmt.Errorf("eddsa_avx: failed to allocate memory")
	}

	if C.ed25519_keygen((*C.uint8_t)(cPubKeyPtr), (*C.uint8_t)(cSecKeyPtr)) != C.EDDSA_KEYGEN_OK {
		C.free(cSecKeyPtr)
		C.free(cPubKeyPtr)
		return nil, errors.New("eddsa_avx: keygen() failed")
	}

	pub := &PublicKey{cPublicKey: (*C.uchar)(cPubKeyPtr)}
	priv := &PrivateKey{cSecretKey: (*C.uchar)(cSecKeyPtr), publicKey: pub}

	runtime.SetFinalizer(priv, func(pk *PrivateKey) {
		C.free(unsafe.Pointer(pk.cSecretKey))
	})
	runtime.SetFinalizer(pub, func(pk *PublicKey) {
		C.free(unsafe.Pointer(pk.cPublicKey))
	})

	return priv, nil
}



func (pub *PublicKey) Bytes() []byte {
	if pub.cPublicKey == nil {
		return nil
	}

	return C.GoBytes(unsafe.Pointer(pub.cPublicKey), C.int(C.ED25519_KEY_SIZE_BYTES_PARAM))
}

func (priv *PrivateKey) Bytes() []byte {
	if priv.cSecretKey == nil {
		return nil
	}

	return C.GoBytes(unsafe.Pointer(priv.cSecretKey), C.int(C.ED25519_KEY_SIZE_BYTES_PARAM))
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.publicKey
}

func Keygen() (pub *PublicKey, priv *PrivateKey, err error) {
	pkc := (*C.uint8_t)(C.malloc(C.ED25519_KEY_SIZE_BYTES_PARAM))
	skc := (*C.uint8_t)(C.malloc(C.ED25519_KEY_SIZE_BYTES_PARAM))

	if pkc == nil || skc == nil {
		return nil, nil, fmt.Errorf("eddsa_avx: failed to allocate memory")
	}

	randkey(skc)

	if C.ed25519_keygen(pkc, skc) != C.EDDSA_KEYGEN_OK {
		C.free(unsafe.Pointer(pkc))
		C.free(unsafe.Pointer(skc))
		return nil, nil, errors.New("eddsa_avx: Keygen failed.")
	}

	pub = &PublicKey{cPublicKey: pkc}
	priv = &PrivateKey{cSecretKey: skc, publicKey: pub}

	runtime.SetFinalizer(pub, func(p *PublicKey) {
		C.free(unsafe.Pointer(p.cPublicKey))
	})
	runtime.SetFinalizer(priv, func(p *PrivateKey) {
		C.free(unsafe.Pointer(p.cSecretKey))
	})

	return pub, priv, nil
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if priv.publicKey == nil || priv.publicKey.cPublicKey == nil {
		return nil, errors.New("eddsa_avx: public key is missing, cannot sign")
	}

	if len(digest) == 0 {
		return nil, errors.New("eddsa_avx: message digest cannot be empty")
	}

	sig_c := C.malloc(C.ED25519_SIG_SIZE_BYTES_PARAM)
	if sig_c == nil {
		return nil, fmt.Errorf("eddsa_avx: failed to allocate memory")
	}
	defer C.free(sig_c)

	msg_c := (*C.uint8_t)(unsafe.Pointer(&digest[0]))

	ret := C.ed25519_sign(
		(*C.uint8_t)(sig_c),
		msg_c,
		(C.uint64_t)(len(digest)),
		priv.publicKey.cPublicKey,
		priv.cSecretKey)

	if ret != C.EDDSA_SIGNATURE_OK {
		return nil, errors.New("eddsa_avx: Sign failed.")
	}

	return C.GoBytes(sig_c, C.int(C.ED25519_SIG_SIZE_BYTES_PARAM)), nil
}

func (pub *PublicKey) Verify(message []byte, signature []byte) (valid bool) {
	if len(signature) != C.ED25519_SIG_SIZE_BYTES_PARAM || len(message) == 0 {
		return false
	}

	msg_c := (*C.uint8_t)(unsafe.Pointer(&message[0]))
	sig_c := (*C.uint8_t)(unsafe.Pointer(&signature[0]))

	ret := C.ed25519_verify(
		msg_c,
		(C.uint64_t)(len(message)),
		pub.cPublicKey,
		sig_c)

	return ret == C.EDDSA_VERIFICATION_OK
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
