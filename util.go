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

// CreateIdentityTokenAddressedTo returns a Replit identity token that proves this Repl's identity
// that includes an audience claim to restrict forwarding.
func CreateIdentityTokenAddressedTo(audience string) (string, error) {
	if os.Getenv("REPL_OWNER") == "five-nine" {
		return "", fmt.Errorf("not logged into Replit, no identity present")
	}

	identitySigningAuthorityToken := os.Getenv("REPL_IDENTITY")
	if identitySigningAuthorityToken == "" {
		return "", fmt.Errorf("no REPL_IDENTITY env var present")
	}
	identitySigningAuthorityKey := os.Getenv("REPL_IDENTITY_KEY")
	if identitySigningAuthorityKey == "" {
		return "", fmt.Errorf("no REPL_IDENTITY_KEY env var present")
	}

	signingAuthority, err := NewSigningAuthority(
		identitySigningAuthorityKey,
		identitySigningAuthorityToken,
		os.Getenv("REPL_ID"),
		ReadPublicKeyFromEnv,
	)
	if err != nil {
		return "", err
	}

	identityToken, err := signingAuthority.Sign(audience)
	if err != nil {
		return "", err
	}

	return identityToken, nil
}
