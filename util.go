package replidentity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/ed25519"
)

// ReadPublicKeyFromEnv provides a [PubKeySource] that reads public keys from the `REPL_PUBKEYS`
// environment variable that is present in all repls.
func ReadPublicKeyFromEnv(keyid, issuer string) (ed25519.PublicKey, error) {
	var pubkeys map[string]json.RawMessage
	err := json.Unmarshal([]byte(os.Getenv("REPL_PUBKEYS")), &pubkeys)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal REPL_PUBKEYS: %w", err)
	}

	pubkey, ok := pubkeys[keyid]
	if !ok {
		// no key
		return nil, nil
	}

	var keyBase64 string
	err = json.Unmarshal(pubkey, &keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal pubkey value: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key as base64: %w", err)
	}

	return ed25519.PublicKey(keyBytes), nil
}

// CreateIdentityTokenSigningAuthority creates a signing authority with this repl's identity key.
func CreateIdentityTokenSigningAuthority() (*SigningAuthority, error) {
	if os.Getenv("REPL_OWNER") == "five-nine" {
		return nil, fmt.Errorf("not logged into Replit, no identity present")
	}

	identitySigningAuthorityToken, identitySigningAuthorityKey := readIdentity()

	if identitySigningAuthorityToken == "" {
		return nil, fmt.Errorf("could not read token from /tmp/replidentity or REPL_IDENTITY env var")
	}

	if identitySigningAuthorityKey == "" {
		return nil, fmt.Errorf("could not read key from /tmp/replidentity.key or REPL_IDENTITY_KEY env var")
	}

	return NewSigningAuthority(
		identitySigningAuthorityKey,
		identitySigningAuthorityToken,
		os.Getenv("REPL_ID"),
		ReadPublicKeyFromEnv,
	)
}

// CreateIdentityTokenAddressedTo returns a Replit identity token that proves this Repl's identity
// that includes an audience claim to restrict forwarding. It creates a new signing authority each
// time, which can be slow. If you plan on signing multiple tokens, use
// CreateIdentityTokenSigningAuthority() to create an authority to sign with.
func CreateIdentityTokenAddressedTo(audience string) (string, error) {
	signingAuthority, err := CreateIdentityTokenSigningAuthority()
	if err != nil {
		return "", err
	}

	if signingAuthority == nil {
		return "", fmt.Errorf("no signing authority could be created")
	}

	identityToken, err := signingAuthority.Sign(audience)
	if err != nil {
		return "", err
	}

	return identityToken, nil
}

// CreateMinimalIdentityTokenAddressedTo returns a minimal Replit identity token with only
// Replid and Aud fields. This creates tokens under 1024 bytes, which is required for
// SSH authentication (OpenSSH password length limit). The minimal token is sufficient
// for SSH authentication as the SSH proxy only verifies the Replid claim.
//
// Use this instead of CreateIdentityTokenAddressedTo when authenticating to SSH with
// username "git" or when the token will be passed as an SSH password via sshpass.
func CreateMinimalIdentityTokenAddressedTo(audience string) (string, error) {
	signingAuthority, err := CreateIdentityTokenSigningAuthority()
	if err != nil {
		return "", err
	}

	if signingAuthority == nil {
		return "", fmt.Errorf("no signing authority could be created")
	}

	identityToken, err := signingAuthority.SignMinimal(audience)
	if err != nil {
		return "", err
	}

	return identityToken, nil
}

// Try to read from /tmp/replidentity and /tmp/replidentity.key,
// falling back to the environment variables.
func readIdentity() (string, string) {
	identity, err := os.ReadFile("/tmp/replidentity")
	if err != nil {
		identity = []byte(os.Getenv("REPL_IDENTITY"))
	}
	identityKey, err := os.ReadFile("/tmp/replidentity.key")
	if err != nil {
		identityKey = []byte(os.Getenv("REPL_IDENTITY_KEY"))
	}

	return string(identity), string(identityKey)
}
