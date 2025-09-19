package replidentity

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// ed25519PrivateKeyToCurve25519 converts a ed25519 private key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/980763a16e30ea5c285c271344d2202fcb18c33b/agessh/agessh.go#L287
func Ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) [32]byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	var res [curve25519.ScalarSize]byte
	copy(res[:], out[:curve25519.ScalarSize])
	return res
}

// ed25519PublicKeyToCurve25519 converts a ed25519 public key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/main/agessh/agessh.go#L190
func Ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([32]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	var res [curve25519.ScalarSize]byte
	if err != nil {
		return res, err
	}
	copy(res[:], p.BytesMontgomery())
	return res, nil
}
