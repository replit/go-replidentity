// Package paserk contains implementations of
// [PASERK](https://github.com/paseto-standard/paserk), an extension to PASETO
// that allows for key sharing. These are not critical security-sensitive, so
// it's fine-ish to implement ourselves to avoid having to add one more
// dependency.
package paserk

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"

	"github.com/replit/go-replidentity/api"
)

const (
	// PaserkPublicHeader is the header of a PASERK public key:
	// https://github.com/paseto-standard/paserk/blob/master/types/public.md
	PaserkPublicHeader = "k2.public."

	// PaserkSecretHeader is the header of a PASERK secret key:
	// https://github.com/paseto-standard/paserk/blob/master/types/secret.md
	PaserkSecretHeader = "k2.secret."

	// PaserkSIDHeader is the header of a PASERK sid:
	// https://github.com/paseto-standard/paserk/blob/master/types/sid.md
	PaserkSIDHeader = "k2.sid."

	// PaserkPIDHeader is the header of a PASERK pid:
	// https://github.com/paseto-standard/paserk/blob/master/types/sid.md
	PaserkPIDHeader = "k2.pid."

	// PaserkGSAIDHeader is the header of a PASERK [api.GovalSigningAuthority] id. This
	// is a replit extension to PASERK.
	PaserkGSAIDHeader = "k2.gsaid."

	// paserkPublicLength is the expected length of a PASERK Public.
	paserkPublicLength = 53

	// paserkSecretLength is the expected length of a PASERK Secret.
	paserkSecretLength = 96
)

// PASERKPublic is the serialized version of an [ed25519.PublicKey]:
// https://github.com/paseto-standard/paserk/blob/master/types/public.md
type PASERKPublic string

// PASERKSecret is the serialized version of an [ed25519.PrivateKey]:
// https://github.com/paseto-standard/paserk/blob/master/types/secret.md
type PASERKSecret string

// PublicKeyToPASERKPublic wraps an [ed25519.PublicKey] into its PASERK representation.
func PublicKeyToPASERKPublic(pubkey ed25519.PublicKey) PASERKPublic {
	return PASERKPublic(PaserkPublicHeader + base64.RawURLEncoding.EncodeToString(pubkey))
}

// PASERKPublicToPublicKey unwraps an [ed25519.PublicKey] from its PASERK representation.
func PASERKPublicToPublicKey(encoded PASERKPublic) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(string(encoded), PaserkPublicHeader) {
		return nil, fmt.Errorf("%q does not have the %q header", encoded, PaserkPublicHeader)
	}
	if len(encoded) != paserkPublicLength {
		return nil, fmt.Errorf("%q is not the expected length of %d", encoded, paserkPublicLength)
	}
	rawKeyData, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(string(encoded), PaserkPublicHeader))
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(rawKeyData), nil
}

// PrivateKeyToPASERKSecret wraps an [ed25519.PrivateKey] into its PASERK representation.
func PrivateKeyToPASERKSecret(privkey ed25519.PrivateKey) PASERKSecret {
	return PASERKSecret(PaserkSecretHeader + base64.RawURLEncoding.EncodeToString(privkey))
}

// PASERKSecretToPrivateKey unwraps an [ed25519.PrivateKey] from its PASERK representation.
func PASERKSecretToPrivateKey(encoded PASERKSecret) (ed25519.PrivateKey, error) {
	if !strings.HasPrefix(string(encoded), PaserkSecretHeader) {
		return nil, fmt.Errorf("%q does not have the %q header", encoded, PaserkSecretHeader)
	}
	if len(encoded) != paserkSecretLength {
		return nil, fmt.Errorf("%q is not the expected length of %d", encoded, paserkSecretLength)
	}
	rawKeyData, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(string(encoded), PaserkSecretHeader))
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(rawKeyData), nil
}

// paserkID implements the PASERK ID operation:
// https://github.com/paseto-standard/paserk/blob/master/operations/ID.md
func paserkID(header, data string) string {
	h, err := blake2b.New(33, nil)
	if err != nil {
		panic(err)
	}
	h.Write([]byte(header))
	h.Write([]byte(data))
	return header + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// PaserkPID returns the PASERK ID of an [ed25519.PublicKey]:
// https://github.com/paseto-standard/paserk/blob/master/types/pid.md
func PaserkPID(pubkey ed25519.PublicKey) string {
	return paserkID(PaserkPIDHeader, string(PublicKeyToPASERKPublic(pubkey)))
}

// PaserkSID returns the PASERK ID of an [ed25519.PrivateKey]:
// https://github.com/paseto-standard/paserk/blob/master/types/sid.md
func PaserkSID(privkey ed25519.PrivateKey) string {
	return paserkID(PaserkSIDHeader, string(PrivateKeyToPASERKSecret(privkey)))
}

// PaserkGSAID returns the PASERK ID of a [api.GovalSigningAuthority]. This is a Replit
// extension to PASERK.
func PaserkGSAID(authority *api.GovalSigningAuthority) string {
	serializedCertProto, err := proto.Marshal(authority)
	if err != nil {
		return ""
	}
	certSerialized := base64.StdEncoding.EncodeToString(serializedCertProto)
	return paserkID(PaserkGSAIDHeader, certSerialized)
}
