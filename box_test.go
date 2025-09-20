package replidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/replit/go-replidentity/paserk"
	"github.com/replit/go-replidentity/protos/external/goval/api"
)

func TestBoxAnonymous(t *testing.T) {
	privkey, identity, err := identityToken("repl", "user", 1, "slug")
	require.NoError(t, err)

	getPubKey := func(keyid, issuer string) (ed25519.PublicKey, error) {
		if keyid != developmentKeyID {
			return nil, nil
		}
		keyBytes, err := base64.StdEncoding.DecodeString(developmentPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key as base64: %w", err)
		}

		return ed25519.PublicKey(keyBytes), nil
	}

	signingAuthority, err := NewSigningAuthority(
		string(paserk.PrivateKeyToPASERKSecret(privkey)),
		identity,
		"repl",
		getPubKey,
	)
	require.NoError(t, err)
	forwarded, err := signingAuthority.Sign("testing")
	require.NoError(t, err)

	verifiedToken, err := VerifyToken(VerifyTokenOpts{
		Message: forwarded,
		Audience: []string{"testing"},
		GetPubKey: getPubKey,
		Flags:     []api.FlagClaim{api.FlagClaim_IDENTITY},
	})
	require.NoError(t, err)

	secret := "secret message"

	sealedBox, err := verifiedToken.SealAnonymousBox([]byte(secret), rand.Reader)
	require.NoError(t, err)

	unsealedBox, err := signingAuthority.OpenAnonymousBox(sealedBox)
	require.NoError(t, err)

	assert.Equal(t, secret, string(unsealedBox))
}
