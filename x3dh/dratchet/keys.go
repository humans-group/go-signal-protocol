package dratchet

import (
	"github.com/humans-group/go-signal-protocol/curve"
	"github.com/humans-group/go-signal-protocol/curve/dh"
	"github.com/humans-group/go-signal-protocol/kdf"
)

// DeriveKeys
// dhs - sending ratchet private key
// dhr - receiving ratchet public key
func DeriveKeys(root *kdf.RootKey, dhs *curve.KeyPair, dhr [32]byte) (*kdf.DerivedKeys, error) {
	secret, err := dh.CalculateSecret(dhs.Private, dhr)
	if err != nil {
		return nil, err
	}

	return kdf.DeriveKeysFromRoot(root, []byte("Ratchet"), secret)
}
