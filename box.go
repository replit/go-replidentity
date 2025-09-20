package replidentity

import (
	"crypto/ed25519"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/replit/go-replidentity/paserk"
)

// SealAnonymousBox encrypts a message using the public key of the certificate.
// Only the private key can decrypt the message.
//
// This uses
// https://pkg.go.dev/golang.org/x/crypto@v0.42.0/nacl/box#SealAnonymous, and
// uses the ed25519 public key embedded in the certificate (converted to
// curve25519 public key).
func (v *VerifiedToken) SealAnonymousBox(message []byte, rand io.Reader) ([]byte, error) {
	pubkey, err := paserk.PASERKPublicToPublicKey(paserk.PASERKPublic(v.Certificate.GetPublicKey()))
	if err != nil {
		return nil, fmt.Errorf("paserk public key to ed25519 public key: %w", err)
	}

	curve25519Pubkey, err := Ed25519PublicKeyToCurve25519(pubkey)
	if err != nil {
		return nil, fmt.Errorf("ed25519 public key to curve25519 public key: %w", err)
	}

	result, err := box.SealAnonymous(
		nil,
		message,
		&curve25519Pubkey,
		rand,
	)
	if err != nil {
		return nil, fmt.Errorf("box.SealAnonymous: %w", err)
	}

	return result, nil
}

// OpenAnonymousBox decrypts a message encrypted with [SealAnonymousBox] using
// the private key of the signature authority.
//
// This uses
// https://pkg.go.dev/golang.org/x/crypto@v0.42.0/nacl/box#OpenAnonymous, and
// uses the ed25519 private key (converted to curve25519 private key).
func (s *SigningAuthority) OpenAnonymousBox(sealedBox []byte) ([]byte, error) {
	curve25519Privkey := Ed25519PrivateKeyToCurve25519(s.privateKey)
	curve25519Pubkey, err := Ed25519PublicKeyToCurve25519(s.privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("ed25519 private key to curve25519 private key: %w", err)
	}

	message, ok := box.OpenAnonymous(nil, sealedBox, &curve25519Pubkey, &curve25519Privkey)
	if !ok {
		return nil, fmt.Errorf("box.OpenAnonymous")
	}

	return message, nil
}
