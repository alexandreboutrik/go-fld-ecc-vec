package main

import (
	"github.com/PQC-Group-UTFPR/go-fld-ecc-vec"
)

import (
	"fmt"
	"C"
)

func main() {
	message  := []byte("Keep Calm and Carry On")
	message_ := []byte("A message")

	// Key generation
	pub , priv , err := eddsa_avx2.Keygen()
	pub_, priv_, _   := eddsa_avx2.Keygen()
	if err != nil {
		panic("Keygen panic.")
	}
	
	fmt.Println("Alice's Private Key:")
	eddsa_avx2.Printkey(priv.CSecretKey)
	fmt.Println("Alice's Public Key:")
	eddsa_avx2.Printkey(pub.CPublicKey)

	// Signature generation
	sig,  err := eddsa_avx2.Sign(message,  pub, priv)
	sig_, _   := eddsa_avx2.Sign(message_, pub_, priv_)
	if err != nil {
		panic("Sign panic.")
	}
	fmt.Println("Ed25519 Signature:")
	fmt.Println(sig)

	// Signature verification
	valid := eddsa_avx2.Verify(message, pub, sig)
	if valid == false {
		fmt.Println("ERROR: Signature invalid.")
	} else {
		fmt.Println("OK: Valid signature.")
	}

	valid = eddsa_avx2.Verify(message_, pub, sig_)
	if valid == false {
		fmt.Println("ERROR: Signature invalid.")
	} else {
		fmt.Println("OK: Valid signature.")
	}
}
