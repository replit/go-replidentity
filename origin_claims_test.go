package replidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/replit/go-replidentity/protos/external/goval/api"
)

func originClaim(t *testing.T, origin string) *api.CertificateClaim {
	t.Helper()
	encoded := protowire.AppendString(protowire.AppendTag(nil, 10, protowire.BytesType), origin)
	var claim api.CertificateClaim
	require.NoError(t, proto.Unmarshal(encoded, &claim))
	return &claim
}

func TestOriginCertificateClaims(t *testing.T) {
	wildcard := &api.CertificateClaim{Claim: &api.CertificateClaim_Flag{Flag: 14}}
	for _, tc := range []struct {
		name   string
		parent *api.CertificateClaim
		child  *api.CertificateClaim
		valid  bool
	}{
		{name: "legacy certificate", valid: true},
		{name: "matching origin", parent: originClaim(t, "source-repl"), child: originClaim(t, "source-repl"), valid: true},
		{name: "wildcard permits origin", parent: wildcard, child: originClaim(t, "source-repl"), valid: true},
		{name: "wildcard permits wildcard", parent: wildcard, child: wildcard, valid: true},
		{name: "different origin", parent: originClaim(t, "source-repl"), child: originClaim(t, "other-repl")},
		{name: "repl wildcard does not permit origin", child: originClaim(t, "source-repl")},
		{name: "specific origin cannot delegate wildcard", parent: originClaim(t, "source-repl"), child: wildcard},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			root := &api.GovalSigningAuthority{
				Cert:    &api.GovalSigningAuthority_KeyId{KeyId: "test-root"},
				Version: api.TokenVersion_TYPE_AWARE_TOKEN,
			}
			parentClaims := []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_SIGN_INTERMEDIATE_CERT}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_REPLID}},
			}
			if tc.parent != nil {
				parentClaims = append(parentClaims, tc.parent)
			}
			parentKey, parent, err := generateIntermediateCert(privateKey, root, parentClaims, "test", time.Hour)
			require.NoError(t, err)
			childClaims := []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Replid{Replid: "build-repl"}},
			}
			if tc.child != nil {
				childClaims = append(childClaims, tc.child)
			}
			childKey, child, err := generateIntermediateCert(parentKey, parent, childClaims, "test", time.Hour)
			require.NoError(t, err)
			identity := &api.GovalReplIdentity{Replid: "build-repl", OriginReplid: "source-repl", Aud: "service"}
			token, err := signIdentity(childKey, child, identity)
			require.NoError(t, err)
			verified, err := VerifyIdentity(token, []string{"service"}, func(string, string) (ed25519.PublicKey, error) {
				return publicKey, nil
			})
			if !tc.valid {
				require.ErrorContains(t, err, "does not authorize claim")
				require.Nil(t, verified)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "build-repl", verified.Replid)
			require.Equal(t, "source-repl", verified.OriginReplid)

			identity.Replid = "source-repl"
			token, err = signIdentity(childKey, child, identity)
			require.NoError(t, err)
			_, err = VerifyIdentity(token, []string{"service"}, func(string, string) (ed25519.PublicKey, error) {
				return publicKey, nil
			})
			require.ErrorContains(t, err, "not authorized (replid)")
		})
	}
}
