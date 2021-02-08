package main

import (
	"fmt"

	"github.com/humans-group/go-signal-protocol/curve"
	"github.com/humans-group/go-signal-protocol/x3dh"
	"github.com/humans-group/go-signal-protocol/x3dh/dratchet"
)

func main() {
	aliceKeys := AliceKeys{
		Ik: newPair(),
		Ek: newPair(),
	}

	ikB := newPair()
	bobKeys := BobKeys{
		Ik:     ikB,
		Spk:    newPair(),
		PreKey: newPair(),
	}

	aliceDK, err := x3dh.DeriveAliceKeys(
		x3dh.Alice{
			IkA:  aliceKeys.Ik.Private,
			EkA:  aliceKeys.Ek.Private,
			IkB:  bobKeys.Ik.Public,
			SpkB: bobKeys.Spk.Public,
			OpkB: &bobKeys.PreKey.Public,
		})
	if err != nil {
		panic(err)
	}

	bobDK, err := x3dh.DeriveBobKeys(
		x3dh.Bob{
			IkB:  bobKeys.Ik.Private,
			SpkB: bobKeys.Spk.Private,
			OpkB: &bobKeys.PreKey.Private,
			IkA:  aliceKeys.Ik.Public,
			EkA:  aliceKeys.Ek.Public,
		})
	if err != nil {
		panic(err)
	}

	aliceSession, err := dratchet.NewAliceSession(aliceDK.Root, aliceKeys.Ik, bobKeys.Ik.Public, bobKeys.Spk.Public)
	if err != nil {
		panic(err)
	}

	alice := namedRatchet{
		name: "alice",
		c:    dratchet.NewController(aliceSession),
	}

	msgA1 := alice.Encrypt("syn")

	bobSession, err := dratchet.NewBobSession(bobDK.Root, bobKeys.Ik, bobKeys.Spk, aliceKeys.Ik.Public, msgA1.RatchetKey)
	if err != nil {
		panic(err)
	}

	bob := namedRatchet{
		name: "bob",
		c:    dratchet.NewController(bobSession),
	}

	bob.Decrypt(msgA1)

	msgA1 = alice.Encrypt("msgsgggg")
	msgA5 := alice.Encrypt("teeest")

	alice.Decrypt(bob.Encrypt("ack"))

	msgA2 := alice.Encrypt("msgA2")
	msgA3 := alice.Encrypt("msgA3")
	msgA4 := alice.Encrypt("msgA4")

	bob.Decrypt(alice.Encrypt("hey there"))

	bob.Decrypt(msgA2)
	bob.Decrypt(msgA3)
	bob.Decrypt(msgA4)
	bob.Decrypt(msgA1)
	bob.Decrypt(msgA5)
}

func newPair() *curve.KeyPair {
	p, err := curve.NewPair()
	if err != nil {
		panic(err)
	}

	return p
}

type AliceKeys struct {
	Ik *curve.KeyPair
	Ek *curve.KeyPair
}

type BobKeys struct {
	Ik     *curve.KeyPair
	Spk    *curve.KeyPair
	PreKey *curve.KeyPair
}

type namedRatchet struct {
	name string
	c    *dratchet.Controller
}

func (r *namedRatchet) Encrypt(str string) *dratchet.CiphertextMessage {
	fmt.Println(r.name, "encrypting:", str)

	msg, err := r.c.Encrypt([]byte(str))
	if err != nil {
		panic(err)
	}

	return msg
}

func (r *namedRatchet) Decrypt(msg *dratchet.CiphertextMessage) string {
	bb, err := r.c.Decrypt(msg)
	if err != nil {
		panic(err)
	}

	str := string(bb)
	fmt.Println(r.name, "decrypted:", str)
	return str
}
