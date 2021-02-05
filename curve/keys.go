package curve

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	Public  [32]byte
	Private [32]byte
}

func NewPair() (*KeyPair, error) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
	}

	// Documented at: http://cr.yp.to/ecdh.html
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return &KeyPair{
		Public:  pub,
		Private: priv,
	}, nil
}
