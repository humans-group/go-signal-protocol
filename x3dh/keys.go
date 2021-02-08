package x3dh

import (
	"github.com/humans-group/go-signal-protocol/curve"
	"github.com/humans-group/go-signal-protocol/curve/eddsa"
)

type SignedPreKey struct {
	Key       *PreKey
	Signature []byte
}

func NewSignedPreKey(signingKey *curve.KeyPair, id int64) (*SignedPreKey, error) {
	preKey, err := NewPreKey(id)
	if err != nil {
		return nil, err
	}

	signature, err := eddsa.Sign(signingKey, preKey.Pair.Public[:])
	if err != nil {
		return nil, err
	}

	return &SignedPreKey{
		Key:       preKey,
		Signature: signature,
	}, nil
}

type PreKey struct {
	ID   int64
	Pair *curve.KeyPair
}

func NewPreKey(id int64) (*PreKey, error) {
	key, err := curve.NewPair()
	if err != nil {
		return nil, err
	}

	return &PreKey{
		ID:   id,
		Pair: key,
	}, nil
}
