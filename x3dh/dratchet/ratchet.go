package dratchet

import (
	"fmt"

	"github.com/humans-group/go-signal-protocol/cipher/cdc"
	"github.com/humans-group/go-signal-protocol/kdf"
)

type Controller struct {
	session *Session
	skipped map[skippedMessageKey]*kdf.MessageKey
}

func NewController(s *Session) *Controller {
	return &Controller{
		session: s,
		skipped: make(map[skippedMessageKey]*kdf.MessageKey),
	}
}

func (c *Controller) Encrypt(plaintext []byte) (*CiphertextMessage, error) {
	mk, err := NewOutgoingMessageKey(c.session)
	if err != nil {
		return nil, err
	}

	ciphertext, err := cdc.Encrypt(mk.Key.Iv, mk.Key.CipherKey, plaintext)
	if err != nil {
		return nil, err
	}

	mac := c.session.Mac.Calculate(mk.Key.MacKey, ciphertext)

	c.session.Send.Rotate()

	return &CiphertextMessage{
		Ciphertext:      ciphertext,
		Mac:             mac,
		Counter:         mk.Key.Index,
		PreviousCounter: mk.PreviousCounter,
		RatchetKey:      mk.RatchetKey,
	}, nil
}

func (c *Controller) Decrypt(msg *CiphertextMessage) ([]byte, error) {
	mk, err := c.incomingMessageKey(msg)
	if err != nil {
		return nil, fmt.Errorf("build incoming message key: %w", err)
	}

	if !c.session.Mac.Verify(msg.Mac, mk.Key.MacKey, msg.Ciphertext) {
		return nil, fmt.Errorf("invalid ciphertext mac")
	}

	plaintext, err := cdc.Decrypt(mk.Key.Iv, mk.Key.CipherKey, msg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	c.finalizeIncomingMessage(mk, msg)

	return plaintext, nil
}

func (c *Controller) incomingMessageKey(msg *CiphertextMessage) (*incomingMessageKey, error) {
	simk, ok, err := c.findSkipped(msg)
	if err != nil {
		return nil, err
	}

	if ok {
		return &incomingMessageKey{
			Key:       simk,
			IsSkipped: true,
		}, nil
	}

	if !c.session.Recv.IsSameKey(msg.RatchetKey) {
		if err := c.skip(msg.PreviousCounter); err != nil {
			return nil, err
		}

		if err := c.rotateSession(msg.RatchetKey); err != nil {
			return nil, fmt.Errorf("rotate session: %w", err)
		}
	}

	if err := c.skip(msg.Counter); err != nil {
		return nil, err
	}

	imk, err := NewIncomingMessageKey(c.session)
	if err != nil {
		return nil, err
	}

	return &incomingMessageKey{Key: imk.Key}, nil
}

func (c *Controller) findSkipped(msg *CiphertextMessage) (*kdf.MessageKey, bool, error) {
	key := newSkippedMessageKey(msg)

	mk, ok := c.skipped[key]
	if !ok {
		return nil, false, nil
	}

	return mk, true, nil
}

func (c *Controller) skip(counter int64) error {
	if c.session.Recv == nil {
		return nil
	}

	if c.session.Recv.Keys.Index()+500 < counter { // TODO: constant
		return fmt.Errorf("too many messages are skipped")
	}

	for c.session.Recv.Keys.Index() < counter {
		mk, err := NewIncomingMessageKey(c.session)
		if err != nil {
			return err
		}

		key := skippedMessageKey{
			key:     mk.RatchetKey,
			counter: mk.Key.Index,
		}
		c.skipped[key] = mk.Key

		c.session.Recv.Rotate()
	}

	return nil
}

func (c *Controller) rotateSession(key [32]byte) error {
	newSession, err := RotateSession(c.session, key)
	if err != nil {
		return err
	}

	c.session = newSession

	return nil
}

func (c *Controller) finalizeIncomingMessage(mk *incomingMessageKey, msg *CiphertextMessage) {
	if mk.IsSkipped {
		delete(c.skipped, newSkippedMessageKey(msg))
		return
	}

	// rotate recv chain as message is not a skipped one
	c.session.Recv.Rotate()
}

type skippedMessageKey struct {
	key     [32]byte
	counter int64
}

func newSkippedMessageKey(msg *CiphertextMessage) skippedMessageKey {
	return skippedMessageKey{
		key:     msg.RatchetKey,
		counter: msg.Counter,
	}
}

type incomingMessageKey struct {
	Key       *kdf.MessageKey
	IsSkipped bool
}

func newMessageKey(ck *kdf.ChainKey) (*kdf.MessageKey, error) {
	return ck.MessageKey([]byte("dratchet message key"))
}

type CiphertextMessage struct {
	Ciphertext      []byte
	Mac             []byte
	Counter         int64
	PreviousCounter int64
	RatchetKey      [32]byte
}
