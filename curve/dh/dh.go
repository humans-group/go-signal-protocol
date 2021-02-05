package dh

import (
	"golang.org/x/crypto/curve25519"
)

func CalculateSecret(priv, pub [32]byte) ([]byte, error) {
	return curve25519.X25519(priv[:], pub[:])
}
