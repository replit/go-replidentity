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
