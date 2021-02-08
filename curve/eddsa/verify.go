package eddsa

import (
	"crypto/ed25519"

	"github.com/teserakt-io/golang-ed25519/edwards25519"
)

func Verify(pub [32]byte, msg, signature []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}

	return verify(pub, msg, signature)
}

func verify(pub [32]byte, msg, signature []byte) bool {
	pub[31] &= 0x7F

	/* Convert the Curve25519 public key into an Ed25519 public key.  In
	particular, convert Curve25519's "montgomery" x-coordinate into an
	Ed25519 "edwards" y-coordinate:

	ed_y = (mont_x - 1) / (mont_x + 1)

	NOTE: mont_x=-1 is converted to ed_y=0 since fe_invert is mod-exp

	Then move the sign bit into the pubkey from the signature.
	*/

	var edY, one, montX, montXMinusOne, montXPlusOne edwards25519.FieldElement
	edwards25519.FeFromBytes(&montX, &pub)
	edwards25519.FeOne(&one)
	edwards25519.FeSub(&montXMinusOne, &montX, &one)
	edwards25519.FeAdd(&montXPlusOne, &montX, &one)
	edwards25519.FeInvert(&montXPlusOne, &montXPlusOne)
	edwards25519.FeMul(&edY, &montXMinusOne, &montXPlusOne)

	var A_ed [32]byte
	edwards25519.FeToBytes(&A_ed, &edY)

	A_ed[31] |= signature[63] & 0x80
	signature[63] &= 0x7F

	return ed25519.Verify(A_ed[:], msg, signature[:])
}
