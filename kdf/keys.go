package kdf

import (
	"fmt"
)

type DerivedKeys struct {
	Chain *ChainKey
	Root  *RootKey
}

func DeriveKeys(info, salt []byte, dhs ...[]byte) (*DerivedKeys, error) {
	fkm := make([]byte, 0, 32*5)
	fkm = append(fkm, diversifier[:]...)
	for i := range dhs {
		fkm = append(fkm, dhs[i]...)
	}

	bb, err := deriveSecret(fkm, salt, info, 64)
	if err != nil {
		return nil, err
	}
	return &DerivedKeys{
		Root:  NewRootKey(bb[:32]),
		Chain: NewChainKey(bb[32:]),
	}, nil
}

func DeriveKeysFromRoot(root *RootKey, info []byte, dhs ...[]byte) (*DerivedKeys, error) {
	return DeriveKeys(info, root.key, dhs...)
}

type RootKey struct {
	key []byte
}

func NewRootKey(key []byte) *RootKey {
	return &RootKey{
		key: key,
	}
}

func (k RootKey) String() string {
	return fmt.Sprintf("%x", k.key)
}

type ChainKey struct {
	index int64
	key   []byte
}

func NewChainKey(key []byte) *ChainKey {
	return &ChainKey{
		index: 0,
		key:   key,
	}
}

func (k *ChainKey) Next() *ChainKey {
	return &ChainKey{
		index: k.index + 1,
		key:   keyMaterial(k.key, nextChainSeed),
	}
}

func (k *ChainKey) MessageKey(info []byte) (*MessageKey, error) {
	km := keyMaterial(k.key, keySeed)

	var salt [80]byte
	out, err := deriveSecret(km, salt[:], info, 80)
	if err != nil {
		return nil, err
	}
	return &MessageKey{
		CipherKey: out[:32],
		MacKey:    out[32:64],
		Iv:        out[64:],
		Index:     k.index,
	}, nil
}

func (k ChainKey) Index() int64 {
	return k.index
}

func (k ChainKey) String() string {
	return fmt.Sprintf("%x(%d)", k.key, k.index)
}

type MessageKey struct {
	CipherKey []byte
	MacKey    []byte
	Iv        []byte
	Index     int64
}
