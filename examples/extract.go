package main

import (
	"fmt"
	"os"

	"github.com/replit/go-replidentity"
)

func main() {
	identity := os.Getenv("REPL_IDENTITY")
	if identity == "" {
		fmt.Println("Sorry, this repl does not yet have an identity (rollout hasn't made it here yet).")
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
