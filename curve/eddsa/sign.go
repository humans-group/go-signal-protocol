package eddsa

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/humans-group/go-signal-protocol/curve"
	"github.com/teserakt-io/golang-ed25519/edwards25519"
)

func Sign(k *curve.KeyPair, msg []byte) ([]byte, error) {
	var random [64]byte
	n, err := io.ReadFull(rand.Reader, random[:])
	if err != nil {
		return nil, err
	}

	if n != len(random) {
		return nil, fmt.Errorf("read bytes count is less than required")
	}

	signature := sign(&k.Private, msg, random)
	return signature[:], nil
}

func sign(privateKey *[32]byte, message []byte, random [64]byte) *[64]byte {

	// Calculate Ed25519 public key from Curve25519 private key
	var A edwards25519.ExtendedGroupElement
	var publicKey [32]byte
	edwards25519.GeScalarMultBase(&A, privateKey)
	A.ToBytes(&publicKey)

	// Calculate r
	diversifier := [32]byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	var r [64]byte
	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(privateKey[:])
	hash.Write(message)
	hash.Write(random[:])
	hash.Sum(r[:0])

	// Calculate R
	var rReduced [32]byte
	edwards25519.ScReduce(&rReduced, &r)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &rReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	// Calculate S = r + SHA2-512(R || A_ed || msg) * a  (mod L)
	var hramDigest [64]byte
	hash.Reset()
	hash.Write(encodedR[:])
	hash.Write(publicKey[:])
	hash.Write(message)
	hash.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, privateKey, &rReduced)

	signature := new([64]byte)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])
	signature[63] |= publicKey[31] & 0x80

	return signature
}
