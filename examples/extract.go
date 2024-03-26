package main

import (
	"fmt"

	"github.com/replit/go-replidentity"
)

func main() {
	// To prevent security problems, every time we prove our identity
	// to another Repl, it needs to be addressed to it, so that the
	// other Repl cannot grab that identity token and spoof you.
	// In order to do that, we need to get that other Repl's `$REPL_ID`.
	audience := "another-cool-repl-id"

	identityToken, err := replidentity.CreateIdentityTokenAddressedTo(audience)
	if err != nil {
		panic(err)
	}

	// The other Repl can now be sent the identityToken and can verify
	// the authenticity of it!
	// In this case, we'll just immediately verify it for demo purposes.

	// audience := os.Getenv("REPL_ID") // uncomment this on the other Repl.
	replIdentity, err := replidentity.VerifyIdentity(
		identityToken,
		[]string{audience},
		replidentity.ReadPublicKeyFromEnv,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("The identity token (%d bytes) is:\n", len(identityToken))
	fmt.Printf("repl id:     %s\n   user:     %s\n   slug:     %s\n   audience: %s\n  ephemeral: %v\n     origin: %v\n", replIdentity.Replid, replIdentity.User, replIdentity.Slug, replIdentity.Aud, replIdentity.Ephemeral, replIdentity.OriginReplid)
}
