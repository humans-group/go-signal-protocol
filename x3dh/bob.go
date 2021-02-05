package x3dh

import (
	"fmt"

	"github.com/humans-group/go-signal-protocol/curve/dh"
	"github.com/humans-group/go-signal-protocol/kdf"
)

type Bob struct {
	IkB  [32]byte  // private identity key
	SpkB [32]byte  // private signed pre key
	OpkB *[32]byte // private one time pre key

	IkA [32]byte // public identity key
	EkA [32]byte // public ephemeral key
}

func DeriveBobKeys(params Bob) (*kdf.DerivedKeys, error) {
	// SKAD
	dh1, err := dh.CalculateSecret(params.SpkB, params.IkA)
	if err != nil {
		return nil, fmt.Errorf("calculate dh1: %w", err)
	}

	dh2, err := dh.CalculateSecret(params.IkB, params.EkA)
	if err != nil {
		return nil, fmt.Errorf("calculate dh2: %w", err)
	}

	dh3, err := dh.CalculateSecret(params.SpkB, params.EkA)
	if err != nil {
		return nil, fmt.Errorf("calculate dh3: %w", err)
	}

	dhs := [][]byte{dh1, dh2, dh3}

	if params.OpkB != nil {
		dh4, err := dh.CalculateSecret(*params.OpkB, params.EkA)
		if err != nil {
			return nil, fmt.Errorf("calculate dh4: %w", err)
		}

		dhs = append(dhs, dh4)
	}

	return kdf.DeriveKeys([]byte("kdf"), nil, dhs...)
}
