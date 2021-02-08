package dratchet

import "github.com/humans-group/go-signal-protocol/kdf"

type SessionChain struct {
	RatchetKey      [32]byte
	Keys            *kdf.ChainKey
	PreviousCounter int64
}

func newSessionChain(key [32]byte, ck *kdf.ChainKey, pcounter int64) *SessionChain {
	return &SessionChain{
		RatchetKey:      key,
		Keys:            ck,
		PreviousCounter: pcounter,
	}
}

func (ch *SessionChain) IsSameKey(key [32]byte) bool {
	if ch == nil {
		return false
	}

	return ch.RatchetKey == key
}

func (ch *SessionChain) Rotate() {
	ch.Keys = ch.Keys.Next()
}
