## Examples

### Extended Triple Diffie-Hellman (X3DH)

[X3DH Reference](https://signal.org/docs/specifications/x3dh)

#### Terminology
* KeyServer - a service providing public key storage capabilities.

#### Participants
* Alice - a person wants to send a message.
* Bob - a person receiving the message.

##### Keys
All the keys are Curve 25519 keys.

* Identity Key (Ik) - long term key. Key is generated once when a participant is created.
* Signed Pre Key (Spk) - middle term key with it's id and signature. [EdDSA](https://signal.org/docs/specifications/xeddsa) scheme is used for generating a pre key signatures.
* One Time Pre Key (Opk) - short term key with it's id. It's supposed to have bunch of keys saved on the server. Each key could be used once.
* Ephemeral Key (Ek) - short term key. The key is generated during each protocol run. It's so named "session" key.

##### Functions

* Curve() - a function generating Curve25519 key pair.
* DH(k1, k2) - [X25519](https://www.ietf.org/rfc/rfc7748.txt) Elliptic Curve Diffie-Hellman function. Calculates a shared secret output from the passed keys.
* KDF(km, salt) - a function representing [HKDF](https://www.ietf.org/rfc/rfc5869.txt) algorithm.
km is a key material used as a concatenation of calculated shared secrets using DH function.
The function calculates two type of keys:
  * root key is used to derive a new chain key.
  * chain key is used to derive a new message key.
* KDF\_CK(chain) - an HKDF function for deriving message keys and a new chain key. A message key consists of four parameters:
  * cipher key - a key used for a plaintext encryption and ciphertext decryption.
  * mac key - a key used for HMAC calculation.
  * initialization vector (IV) - a parameter used for a chosen encryption algorithm.
  * index - a counter for an appropriate chain key. The counter is increased when chain key is updated. The counter is used for out-of-order messages processing.
* Encrypt(messageKey, plaintext) - returns encryption of plaintext using the given parameters from a message key.
* Decrypt(messageKey, ciphertext) - returns decryption of ciphertext using the given parameters from a message key.
* Sign(ikB, spkB) - an EdDSA function returning signature of the specified signed pre key.
* Verify(ikB, spkB, sign) - an EdDSA function used to verify the given signature of a signed pre key by the specified identity key.


#### Protocol run

[Sequence diagramm]()

##### Communication

[Double ratchet](https://signal.org/docs/specifications/doubleratchet/)

#### Multiple devices (TODO)