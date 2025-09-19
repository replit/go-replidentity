package replidentity_test

import (
	"fmt"
	"os"

	"github.com/replit/go-replidentity"
)

func Example() {
	identity := os.Getenv("REPL_IDENTITY")
	if identity == "" {
		fmt.Println("Sorry, this repl does not yet have an identity (anonymous run?).")
		return
	}
	identityKey := os.Getenv("REPL_IDENTITY_KEY")
	if identity == "" {
		fmt.Println("Sorry, this repl does not yet have an identity (anonymous run?).")
		return
	}

	// This should be set to the Repl ID of the repl you want to prove your
	// identity to.
	targetRepl := "target_repl"

	// Create a signing authority that is authorized to emit tokens for the
	// current repl.
	signingAuthority, err := replidentity.NewSigningAuthority(
		string(identityKey),
		identity,
		os.Getenv("REPL_ID"),
		replidentity.ReadPublicKeyFromEnv,
	)
	if err != nil {
		panic(err)
	}

	signedToken, err := signingAuthority.Sign(targetRepl)
	if err != nil {
		panic(err)
	}

	// Verify the signed token, pretending we are the target repl.
	replIdentity, err := replidentity.VerifyIdentity(
		signedToken,
		[]string{targetRepl},
		replidentity.ReadPublicKeyFromEnv,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("The identity in the repl's token (%d bytes) is:\n", len(identity))
	fmt.Printf(
		"repl id: %s\n   user: %s\n   slug: %s  audience: %s\n",
		replIdentity.Replid,
		replIdentity.User,
		replIdentity.Slug,
		replIdentity.Aud,
	)
}

func ExampleVerifyRenewIdentity() {
	identity := os.Getenv("REPL_RENEWAL")
	if identity == "" {
		fmt.Println("Sorry, this repl does not yet have an identity (anonymous run?).")
		return
	}
	identityKey := os.Getenv("REPL_RENEWAL_KEY")
	if identity == "" {
		fmt.Println("Sorry, this repl does not yet have an identity (anonymous run?).")
		return
	}

	// This should be set to the Repl ID of the repl you want to prove your
	// identity to.
	targetRepl := "target_repl"

	// Create a signing authority that is authorized to emit tokens for the
	// current repl.
	signingAuthority, err := replidentity.NewSigningAuthority(
		string(identityKey),
		identity,
		os.Getenv("REPL_ID"),
		replidentity.ReadPublicKeyFromEnv,
	)
	if err != nil {
		panic(err)
	}

	signedToken, err := signingAuthority.Sign(targetRepl)
	if err != nil {
		panic(err)
	}

	// Verify the signed token, pretending we are the target repl.
	replIdentity, err := replidentity.VerifyRenewIdentity(
		signedToken,
		[]string{targetRepl},
		replidentity.ReadPublicKeyFromEnv,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("The identity in the repl's token (%d bytes) is:\n", len(identity))
	fmt.Printf(
		"repl id: %s\n   user: %s\n   slug: %s  audience: %s\n",
		replIdentity.Replid,
		replIdentity.User,
		replIdentity.Slug,
		replIdentity.Aud,
	)
}
