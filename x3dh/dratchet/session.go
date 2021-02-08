package dratchet

import (
	"fmt"

	"github.com/humans-group/go-signal-protocol/curve"
	"github.com/humans-group/go-signal-protocol/kdf"
)

type Session struct {
	RootKey *kdf.RootKey
	LastKey *curve.KeyPair
	Recv    *SessionChain
	Send    *SessionChain
	Mac     *CiphertextMac
}

func NewAliceSession(rk *kdf.RootKey, ikA *curve.KeyPair, ikB, spkB [32]byte) (*Session, error) {
	newKey, err := curve.NewPair()
	if err != nil {
		return nil, err
	}

	send, err := DeriveKeys(rk, newKey, spkB)
	if err != nil {
		return nil, err
	}

	rk = send.Root

	return &Session{
		RootKey: rk,
		LastKey: newKey,
		Send:    newSessionChain(newKey.Public, send.Chain, 0),
		Mac:     NewCiphertextMac(ikA.Public, ikB),
	}, nil
}

func NewBobSession(rk *kdf.RootKey, ikB, spkB *curve.KeyPair, ikA, ratchetKeyA [32]byte) (*Session, error) {
	recv, err := DeriveKeys(rk, spkB, ratchetKeyA)
	if err != nil {
		return nil, err
	}

	rk = recv.Root
	newKey, err := curve.NewPair()
	if err != nil {
		return nil, err
	}

	send, err := DeriveKeys(rk, newKey, ratchetKeyA)
	if err != nil {
		return nil, err
	}

	rk = send.Root
	return &Session{
		RootKey: rk,
		LastKey: newKey,
		Recv:    newSessionChain(ratchetKeyA, recv.Chain, 0),
		Send:    newSessionChain(newKey.Public, send.Chain, 0),
		Mac:     NewCiphertextMac(ikB.Public, ikA),
	}, nil
}

func RotateSession(s *Session, newRecvKey [32]byte) (*Session, error) {
	rootKey := s.RootKey
	newRecv, err := DeriveKeys(s.RootKey, s.LastKey, newRecvKey)
	if err != nil {
		return nil, fmt.Errorf("derive recv keys: %w", err)
	}

	rootKey = newRecv.Root
	var recvPreviousCounter int64
	if s.Recv != nil {
		recvPreviousCounter = s.Recv.Keys.Index()
	}

	newRecvChain := newSessionChain(newRecvKey, newRecv.Chain, recvPreviousCounter)

	// TODO: create sending chain once needed
	newKey, err := curve.NewPair()
	if err != nil {
		return nil, fmt.Errorf("new ratchet key pair: %w", err)
	}

	newSend, err := DeriveKeys(rootKey, newKey, newRecvKey)
	if err != nil {
		return nil, fmt.Errorf("derive send keys: %w", err)
	}

	rootKey = newSend.Root
	sendPreviousCounter := s.Send.Keys.Index()
	newSendChain := newSessionChain(newKey.Public, newSend.Chain, sendPreviousCounter)

	return &Session{
		RootKey: rootKey,
		LastKey: newKey,
		Recv:    newRecvChain,
		Send:    newSendChain,
		Mac:     s.Mac,
	}, nil
}

type OutgoingMessageKey struct {
	Key             *kdf.MessageKey
	RatchetKey      [32]byte
	PreviousCounter int64
}

func NewOutgoingMessageKey(s *Session) (OutgoingMessageKey, error) {
	mk, err := newMessageKey(s.Send.Keys)
	if err != nil {
		return OutgoingMessageKey{}, err
	}

	return OutgoingMessageKey{
		Key:             mk,
		RatchetKey:      s.Send.RatchetKey,
		PreviousCounter: s.Send.PreviousCounter,
	}, nil
}

type IncomingMessageKey struct {
	Key        *kdf.MessageKey
	RatchetKey [32]byte
}

func NewIncomingMessageKey(s *Session) (IncomingMessageKey, error) {
	mk, err := newMessageKey(s.Recv.Keys)
	if err != nil {
		return IncomingMessageKey{}, nil
	}

	return IncomingMessageKey{
		Key:        mk,
		RatchetKey: s.Recv.RatchetKey,
	}, nil
}
