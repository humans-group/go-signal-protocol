package dratchet

import (
	"crypto/hmac"
	"crypto/sha256"
)

type CiphertextMac struct {
	senderIdentityKey   [32]byte
	receiverIdentityKey [32]byte
}

func NewCiphertextMac(sendIK, recvIK [32]byte) *CiphertextMac {
	return &CiphertextMac{
		senderIdentityKey:   sendIK,
		receiverIdentityKey: recvIK,
	}
}

func (m *CiphertextMac) Calculate(key, ciphertext []byte) []byte {
	return calculateMac(
		key,
		m.senderIdentityKey[:],
		m.receiverIdentityKey[:],
		ciphertext)
}

func (m *CiphertextMac) Verify(mac, key, ciphertext []byte) bool {
	wantMac := calculateMac(key,
		m.receiverIdentityKey[:],
		m.senderIdentityKey[:],
		ciphertext)

	return hmac.Equal(mac, wantMac)
}

func calculateMac(key, senderKey, receiverKey, ciphertext []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(senderKey)
	mac.Write(receiverKey)
	mac.Write(ciphertext)
	fullMac := mac.Sum(nil)

	if len(fullMac) > macLen {
		fullMac = fullMac[:macLen]
	}

	return fullMac
}

const (
	macLen = 8
)
