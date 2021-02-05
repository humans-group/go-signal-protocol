package x3dh

import (
	"fmt"

	"github.com/humans-group/go-signal-protocol/curve/dh"
	"github.com/humans-group/go-signal-protocol/kdf"
)

type Alice struct {
	IkA [32]byte // private identity key
	EkA [32]byte // private ephemeral key

	IkB  [32]byte  // public identity key
	SpkB [32]byte  // public signed pre key
	OpkB *[32]byte // public one time pre key
}

func DeriveAliceKeys(params Alice) (*kdf.DerivedKeys, error) {
	dh1, err := dh.CalculateSecret(params.IkA, params.SpkB)
	if err != nil {
		return nil, fmt.Errorf("calculate dh1: %w", err)
	}

	dh2, err := dh.CalculateSecret(params.EkA, params.IkB)
	if err != nil {
		return nil, fmt.Errorf("calculate dh2: %w", err)
	}

	dh3, err := dh.CalculateSecret(params.EkA, params.SpkB)
	if err != nil {
		return nil, fmt.Errorf("calculate dh3: %w", err)
	}

	dhs := [][]byte{dh1, dh2, dh3}

	if params.OpkB != nil {
		dh4, err := dh.CalculateSecret(params.EkA, *params.OpkB)
		if err != nil {
			return nil, fmt.Errorf("calculate dh4: %w", err)
		}

		dhs = append(dhs, dh4)
	}

	return kdf.DeriveKeys([]byte("kdf"), nil, dhs...)
}
