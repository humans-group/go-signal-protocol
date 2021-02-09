package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func Encrypt(iv, key, bb []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded, err := pkcs7Pad(bb, block.BlockSize())
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

func Decrypt(iv, key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	bb, err := pkcs7Unpad(ciphertext, block.BlockSize())
	if err != nil {
		return nil, err
	}

	return bb, nil
}

func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		panic("block size is invalid")
	}
	if len(b) == 0 {
		panic("data slice is empty")
	}

	n := blocksize - (len(b) % blocksize)
	padded := append(b, bytes.Repeat([]byte{byte(n)}, n)...)
	return padded, nil
}

func pkcs7Unpad(ciphertext []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		panic("block size is invalid")
	}

	if len(ciphertext) == 0 {
		panic("ciphertext size is zero")
	}

	if len(ciphertext)%blocksize != 0 {
		return nil, errInvalidCiphertext
	}

	c := ciphertext[len(ciphertext)-1]
	n := int(c)
	if n == 0 || n > len(ciphertext) {
		return nil, errInvalidCiphertext
	}
	for i := 0; i < n; i++ {
		if ciphertext[len(ciphertext)-n+i] != c {
			return nil, errInvalidCiphertext
		}
	}
	return ciphertext[:len(ciphertext)-n], nil
}

var errInvalidCiphertext = fmt.Errorf("ciphertext is invalid")
