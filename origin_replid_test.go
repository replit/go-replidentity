package replidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/replit/go-replidentity/protos/external/goval/api"
)

func TestOriginReplIDClaimsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims []*api.CertificateClaim
	}{
		{"legacy", []*api.CertificateClaim{{Claim: &api.CertificateClaim_Replid{Replid: "runtime"}}}},
		{"origins", []*api.CertificateClaim{
			{Claim: &api.CertificateClaim_OriginReplid{OriginReplid: "source-a"}},
			{Claim: &api.CertificateClaim_OriginReplid{OriginReplid: "source-b"}},
		}},
		{"any origin", []*api.CertificateClaim{{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &api.GovalCert{Claims: tc.claims}
			data, err := proto.Marshal(cert)
			require.NoError(t, err)
			var decoded api.GovalCert
			require.NoError(t, proto.Unmarshal(data, &decoded))
			require.True(t, proto.Equal(cert, &decoded))
			claims := parseClaims(&decoded)
			switch tc.name {
			case "legacy":
				require.Contains(t, claims.Repls, "runtime")
				require.Empty(t, claims.OriginRepls)
				require.NotContains(t, claims.Flags, api.FlagClaim_ANY_ORIGIN_REPLID)
			case "origins":
				require.Len(t, claims.OriginRepls, 2)
				require.Contains(t, claims.OriginRepls, "source-a")
				require.Contains(t, claims.OriginRepls, "source-b")
				require.Empty(t, claims.Repls)
			case "any origin":
				require.Contains(t, claims.Flags, api.FlagClaim_ANY_ORIGIN_REPLID)
				require.Empty(t, claims.OriginRepls)
			}
		})
	}
}

func TestOriginReplIDWireValues(t *testing.T) {
	for _, tc := range []struct {
		claim *api.CertificateClaim
		wire  []byte
	}{
		{&api.CertificateClaim{Claim: &api.CertificateClaim_OriginReplid{OriginReplid: "source"}}, []byte{0x52, 6, 's', 'o', 'u', 'r', 'c', 'e'}},
		{&api.CertificateClaim{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}}, []byte{0x18, 14}},
	} {
		wire, err := proto.Marshal(tc.claim)
		require.NoError(t, err)
		require.Equal(t, tc.wire, wire)
	}
}

func TestOriginReplIDCertificateDelegation(t *testing.T) {
	origin := &api.CertificateClaim{Claim: &api.CertificateClaim_OriginReplid{OriginReplid: "source"}}
	otherOrigin := &api.CertificateClaim{Claim: &api.CertificateClaim_OriginReplid{OriginReplid: "other"}}
	anyOrigin := &api.CertificateClaim{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}}
	anyRepl := &api.CertificateClaim{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_REPLID}}
	for _, tc := range []struct {
		name   string
		parent *api.CertificateClaim
		child  *api.CertificateClaim
		valid  bool
	}{
		{"matching origin", origin, origin, true},
		{"different origin", origin, otherOrigin, false},
		{"wildcard to origin", anyOrigin, origin, true},
		{"wildcard to wildcard", anyOrigin, anyOrigin, true},
		{"origin cannot widen", origin, anyOrigin, false},
		{"repl wildcard is separate", anyRepl, origin, false},
		{"legacy certificates", anyRepl, anyRepl, true},
		{"legacy parent cannot authorize origin", nil, origin, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := &api.GovalCert{Claims: []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_SIGN_INTERMEDIATE_CERT}},
			}}
			if tc.parent != nil {
				parent.Claims = append(parent.Claims, tc.parent)
			}
			child := &api.GovalCert{
				Iat:    timestamppb.New(time.Now().Add(-time.Minute)),
				Exp:    timestamppb.New(time.Now().Add(time.Hour)),
				Claims: []*api.CertificateClaim{tc.child},
			}
			data, err := proto.Marshal(child)
			require.NoError(t, err)
			v := &verifier{}
			_, err = v.verifyCert(data, parent)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, parseClaims(child), v.claims)
			} else {
				require.ErrorContains(t, err, "does not authorize claim")
			}
		})
	}
}

// verifyOriginToken mints an identity whose body claims bodyOrigin under a
// certificate carrying extraClaims, and returns the verification error (nil
// on success). The chain is root key -> intermediate -> leaf, matching
// production: only non-root-signed certs have their any-* flags honored.
func verifyOriginToken(t *testing.T, extraClaims []*api.CertificateClaim, bodyOrigin string) error {
	t.Helper()

	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootAuthority := &api.GovalSigningAuthority{
		Issuer: "test",
		Cert:   &api.GovalSigningAuthority_KeyId{KeyId: "origin-test:1"},
	}

	midPrivateKey, midAuthority, err := generateIntermediateCert(rootPrivateKey, rootAuthority, []*api.CertificateClaim{
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_SIGN_INTERMEDIATE_CERT}},
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_REPLID}},
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_USER}},
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_USER_ID}},
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}},
	}, "test", time.Hour)
	require.NoError(t, err)

	claims := append([]*api.CertificateClaim{
		{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
		{Claim: &api.CertificateClaim_Replid{Replid: "repl"}},
		{Claim: &api.CertificateClaim_User{User: "user"}},
		{Claim: &api.CertificateClaim_UserId{UserId: 1}},
	}, extraClaims...)
	leafPriv, leafAuthority, err := generateIntermediateCert(midPrivateKey, midAuthority, claims, "test", time.Hour)
	require.NoError(t, err)

	identity := api.GovalReplIdentity{
		Replid:       "repl",
		User:         "user",
		UserId:       1,
		Slug:         "slug",
		Aud:          "aud",
		OriginReplid: bodyOrigin,
	}
	token, err := signIdentity(leafPriv, leafAuthority, &identity)
	require.NoError(t, err)

	_, err = VerifyIdentity(token, []string{"aud"}, func(keyid, issuer string) (ed25519.PublicKey, error) {
		return rootPublicKey, nil
	})
	return err
}

func TestOriginReplIDBodyBinding(t *testing.T) {
	originClaim := &api.CertificateClaim{Claim: &api.CertificateClaim_OriginReplid{OriginReplid: "source"}}
	anyOrigin := &api.CertificateClaim{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_ORIGIN_REPLID}}

	for _, tc := range []struct {
		name        string
		claims      []*api.CertificateClaim
		bodyOrigin  string
		errContains string
	}{
		// The vulnerability: a repl signs a token whose body claims an origin
		// its certificate never authorized.
		{"uncertified origin rejected", nil, "evil", "not authorized (originReplid)"},
		{"different origin rejected", []*api.CertificateClaim{originClaim}, "other", "not authorized (originReplid)"},
		{"certified origin accepted", []*api.CertificateClaim{originClaim}, "source", ""},
		{"any origin accepts any", []*api.CertificateClaim{anyOrigin}, "anything", ""},
		{"legacy cert with no body origin", nil, "", ""},
		{"certified origin with empty body origin", []*api.CertificateClaim{originClaim}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyOriginToken(t, tc.claims, tc.bodyOrigin)
			if tc.errContains == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.errContains)
			}
		})
	}
}
