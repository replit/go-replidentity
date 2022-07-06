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

	replIdentity, err := replidentity.VerifyIdentity(identity, replidentity.ReadPublicKeyFromEnv)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("The identity in the repl's REPL_IDENTITY token (%d bytes) is:\n", len(identity))
	fmt.Printf("repl id: %s\n   user: %s\n   slug: %s\n", replIdentity.Replid, replIdentity.User, replIdentity.Slug)
}
