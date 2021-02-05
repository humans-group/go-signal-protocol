package dratchet

import (
	"fmt"

	"github.com/humans-group/go-signal-protocol/cipher/cdc"
	"github.com/humans-group/go-signal-protocol/curve"
	"github.com/humans-group/go-signal-protocol/kdf"
)

type State struct {
	rootKey    *kdf.RootKey
	ratchetKey *curve.KeyPair
	recv       chain
	send       chain
	skipped    map[skippedMessageKey]*kdf.MessageKey
}

func NewAliceState(rootKey *kdf.RootKey, spkB [32]byte) (*State, error) {
	newKey, err := curve.NewPair()
	if err != nil {
		return nil, err
	}

	send, err := DeriveKeys(rootKey, newKey, spkB)
	if err != nil {
		return nil, err
	}

	rootKey = send.Root
	return &State{
		rootKey:    rootKey,
		ratchetKey: newKey,
		send:       newChain(newKey.Public, send.Chain, 0),
		skipped:    make(map[skippedMessageKey]*kdf.MessageKey),
	}, nil
}

func NewBobState(rootKey *kdf.RootKey, spkB *curve.KeyPair, ratchetKeyA [32]byte) (*State, error) {
	recv, err := DeriveKeys(rootKey, spkB, ratchetKeyA)
	if err != nil {
		return nil, err
	}

	rootKey = recv.Root
	newKey, err := curve.NewPair()
	if err != nil {
		return nil, err
	}

	send, err := DeriveKeys(rootKey, newKey, ratchetKeyA)
	if err != nil {
		return nil, err
	}

	rootKey = send.Root
	return &State{
		rootKey:    rootKey,
		ratchetKey: newKey,
		recv:       newChain(ratchetKeyA, recv.Chain, 0),
		send:       newChain(newKey.Public, send.Chain, 0),
		skipped:    make(map[skippedMessageKey]*kdf.MessageKey),
	}, nil
}

func (s *State) Encrypt(message []byte) (*CiphertextMessage, error) {
	mk, err := newMessageKey(s.send.Keys)
	if err != nil {
		return nil, err
	}

	ciphertext, err := cdc.Encrypt(mk.Iv, mk.CipherKey, message)
	if err != nil {
		return nil, err
	}

	s.send.Rotate()

	return &CiphertextMessage{
		Ciphertext:      ciphertext,
		Counter:         mk.Index,
		PreviousCounter: s.send.PreviousCounter,
		RatchetKey:      s.send.RatchetKey,
	}, nil
}

func (s *State) Decrypt(msg *CiphertextMessage) ([]byte, error) {
	plainText, ok, err := s.decryptSkipped(msg)
	if err != nil {
		return nil, fmt.Errorf("decrypt skipped: %w", err)
	}

	if ok {
		return plainText, nil
	}

	// sending key from other side has changed
	if !s.recv.IsSameKey(msg.RatchetKey) {
		if err := s.skip(msg.PreviousCounter); err != nil {
			return nil, err
		}

		if err := s.rotate(msg.RatchetKey); err != nil {
			return nil, err
		}
	}

	if err := s.skip(msg.Counter); err != nil {
		return nil, err
	}

	mk, err := newMessageKey(s.recv.Keys)
	if err != nil {
		return nil, err
	}

	message, err := s.decrypt(mk, msg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	s.recv.Rotate()

	return message, nil
}

func (s *State) rotate(pub [32]byte) error {
	rootKey := s.rootKey
	newRecv, err := DeriveKeys(s.rootKey, s.ratchetKey, pub)
	if err != nil {
		return fmt.Errorf("derive recv keys: %w", err)
	}

	rootKey = newRecv.Root
	var recvPreviousCounter int64
	if s.recv.Keys != nil {
		recvPreviousCounter = s.recv.Keys.Index()
	}

	s.recv = newChain(pub, newRecv.Chain, recvPreviousCounter)

	newKey, err := curve.NewPair()
	if err != nil {
		return fmt.Errorf("new ratchet key pair: %w", err)
	}

	newSend, err := DeriveKeys(rootKey, newKey, pub)
	if err != nil {
		return fmt.Errorf("derive send keys: %w", err)
	}

	rootKey = newSend.Root
	s.send = newChain(newKey.Public, newSend.Chain, s.send.Keys.Index())
	s.ratchetKey = newKey

	return nil
}

func (s *State) decryptSkipped(msg *CiphertextMessage) ([]byte, bool, error) {
	key := skippedMessageKey{
		key:     msg.RatchetKey,
		counter: msg.Counter,
	}

	mk, ok := s.skipped[key]
	if !ok {
		return nil, false, nil
	}

	bb, err := s.decrypt(mk, msg.Ciphertext)
	if err != nil {
		return nil, false, err
	}

	delete(s.skipped, key)

	return bb, true, nil
}

func (s *State) decrypt(mk *kdf.MessageKey, ciphertext []byte) ([]byte, error) {
	return cdc.Decrypt(mk.Iv, mk.CipherKey, ciphertext)
}

func (s *State) skip(counter int64) error {
	if !s.recv.Valid {
		return nil
	}

	if s.recv.Keys.Index()+500 < counter { // TODO: constant
		return fmt.Errorf("too many messages are skipped")
	}

	for s.recv.Keys.Index() < counter {
		mk, err := newMessageKey(s.recv.Keys)
		if err != nil {
			return err
		}

		key := skippedMessageKey{
			key:     s.recv.RatchetKey,
			counter: mk.Index,
		}
		s.skipped[key] = mk

		s.recv.Rotate()
	}

	return nil
}

func newMessageKey(ck *kdf.ChainKey) (*kdf.MessageKey, error) {
	return ck.MessageKey([]byte("dratchet message key"))
}

type CiphertextMessage struct {
	Ciphertext      []byte
	Counter         int64
	PreviousCounter int64
	RatchetKey      [32]byte
}

type chain struct {
	Valid           bool
	RatchetKey      [32]byte
	Keys            *kdf.ChainKey
	PreviousCounter int64
}

func newChain(key [32]byte, ck *kdf.ChainKey, pcounter int64) chain {
	return chain{
		Valid:           true,
		RatchetKey:      key,
		Keys:            ck,
		PreviousCounter: pcounter,
	}
}

func (ch *chain) IsSameKey(key [32]byte) bool {
	return ch.RatchetKey == key
}

func (ch *chain) Rotate() {
	ch.Keys = ch.Keys.Next()
}

type skippedMessageKey struct {
	key     [32]byte
	counter int64
}
