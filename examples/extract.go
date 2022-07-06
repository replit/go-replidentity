package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/replit/go-replidentity"
	"golang.org/x/crypto/ed25519"
)

func main() {
	identity := os.Getenv("REPL_IDENTITY")
	if identity == "" {
		fmt.Println("Sorry, this repl does not yet have an identity (rollout hasn't made it here yet).")
		return
	}

	replIdentity, err := replidentity.VerifyIdentity(identity, readPublicKeyFromEnv)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("The identity in the repl's REPL_IDENTITY token (%d bytes) is:\n", len(identity))
	fmt.Printf("repl id: %s\n   user: %s\n   slug: %s\n", replIdentity.Replid, replIdentity.User, replIdentity.Slug)
}

func readPublicKeyFromEnv(keyid, issuer string) (ed25519.PublicKey, error) {
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
