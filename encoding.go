package replidentity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func pemToPubkey(key string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key: %s", key)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	pubkey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unknown pubkey type: %T", pub)
	}

	return pubkey, nil
}
