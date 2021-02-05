package kdf

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func deriveSecret(km, salt, info []byte, size int) ([]byte, error) {
	reader := hkdf.New(sha256.New, km, salt, info)

	secret := make([]byte, size)
	n, err := io.ReadFull(reader, secret)
	if err != nil {
		return nil, err
	}

	if n != size {
		return nil, fmt.Errorf("read n != size")
	}

	return secret, nil
}
