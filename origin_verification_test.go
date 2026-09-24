package replidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/replit/go-replidentity/protos/external/goval/api"
)

func TestOriginVerification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		claims    []*api.CertificateClaim
		origin    string
		buildInfo *api.BuildInfo
		result    OriginVerificationResult
	}{
		{name: "bound origin", claims: []*api.CertificateClaim{originClaim(t, "source-repl")}, origin: "source-repl", result: OriginVerified},
		{name: "bound empty origin", claims: []*api.CertificateClaim{originClaim(t, "")}, result: OriginVerified},
		{name: "legacy origin", origin: "source-repl", result: OriginMissingClaim},
		{name: "legacy empty origin", result: OriginMissingClaim},
		{name: "changed origin", claims: []*api.CertificateClaim{originClaim(t, "source-repl")}, origin: "other-repl", result: OriginMismatch},
		{name: "stripped origin", claims: []*api.CertificateClaim{originClaim(t, "source-repl")}, result: OriginMismatch},
		{name: "added origin", claims: []*api.CertificateClaim{originClaim(t, "")}, origin: "other-repl", result: OriginMismatch},
		{name: "matching build origin", claims: []*api.CertificateClaim{originClaim(t, "source-repl")}, origin: "source-repl", buildInfo: &api.BuildInfo{OriginReplId: "source-repl"}, result: OriginVerified},
		{name: "legacy build info", claims: []*api.CertificateClaim{originClaim(t, "source-repl")}, origin: "source-repl", buildInfo: &api.BuildInfo{DeploymentId: "deployment"}, result: OriginVerified},
		{name: "changed build origin", claims: []*api.CertificateClaim{originClaim(t, "source-repl")}, origin: "source-repl", buildInfo: &api.BuildInfo{OriginReplId: "other-repl"}, result: OriginBuildInfoMismatch},
		{name: "leaf wildcard", claims: []*api.CertificateClaim{{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}}}, origin: "source-repl", result: OriginVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			authority := &api.GovalSigningAuthority{
				Cert:    &api.GovalSigningAuthority_KeyId{KeyId: "test-root"},
				Version: api.TokenVersion_TYPE_AWARE_TOKEN,
			}
			parentClaims := []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_SIGN_INTERMEDIATE_CERT}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_RENEW_IDENTITY}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_REPLID}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}},
			}
			for range 2 {
				privateKey, authority, err = generateIntermediateCert(privateKey, authority, parentClaims, "test", time.Hour)
				require.NoError(t, err)
			}
			leafClaims := append([]*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_RENEW_IDENTITY}},
				{Claim: &api.CertificateClaim_Replid{Replid: "build-repl"}},
			}, tc.claims...)
			privateKey, authority, err = generateIntermediateCert(privateKey, authority, leafClaims, "test", time.Hour)
			require.NoError(t, err)
			token, err := signIdentity(privateKey, authority, &api.GovalReplIdentity{
				Replid: "build-repl", OriginReplid: tc.origin, BuildInfo: tc.buildInfo, Aud: "service",
			})
			require.NoError(t, err)
			getKey := func(string, string) (ed25519.PublicKey, error) { return publicKey, nil }

			for _, verify := range []struct {
				name string
				call func(string, []string, PubKeySource, ...VerifyOption) (*api.GovalReplIdentity, error)
			}{
				{name: "identity", call: VerifyIdentity},
				{name: "renewal", call: VerifyRenewIdentity},
			} {
				t.Run(verify.name, func(t *testing.T) {
					var observed OriginVerificationResult
					identity, err := verify.call(token, []string{"service"}, getKey, WithOriginVerification(false, func(result OriginVerificationResult) {
						observed = result
					}))
					require.NoError(t, err)
					require.Equal(t, tc.origin, identity.OriginReplid)
					require.Equal(t, tc.result, observed)

					identity, err = verify.call(token, []string{"service"}, getKey, WithOriginVerification(true, nil))
					if tc.result == OriginVerified {
						require.NoError(t, err)
						require.Equal(t, tc.origin, identity.OriginReplid)
					} else {
						require.ErrorContains(t, err, "not authorized (originReplid): "+string(tc.result))
						require.Nil(t, identity)
					}
				})
			}
		})
	}
}

func TestRootSignedOrigin(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authority := &api.GovalSigningAuthority{
		Cert:    &api.GovalSigningAuthority_KeyId{KeyId: "test-root"},
		Version: api.TokenVersion_TYPE_AWARE_TOKEN,
	}
	token, err := signIdentity(privateKey, authority, &api.GovalReplIdentity{
		Replid: "repl", OriginReplid: "source-repl", Aud: "service",
	})
	require.NoError(t, err)
	verified, err := VerifyToken(VerifyTokenOpts{
		Message:   token,
		Audience:  []string{"service"},
		GetPubKey: func(string, string) (ed25519.PublicKey, error) { return publicKey, nil },
		Options:   []VerifyOption{WithOriginVerification(true, nil)},
	})
	require.NoError(t, err)
	require.Equal(t, "source-repl", verified.Identity.OriginReplid)
}
