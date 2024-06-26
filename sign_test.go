package replidentity

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/o1egl/paseto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/replit/go-replidentity/paserk"
	"github.com/replit/go-replidentity/protos/external/goval/api"
)

const (
	developmentKeyID     = "dev:1"
	developmentPublicKey = "on0FkSmEC+ce40V9Vc4QABXSx6TXo+lhp99b6Ka0gro="
	conmanPrivateKey     = "mRe4Bu9PG4Tq52M6LXp2oRcljhOjhJ43+x4AjPsPHaOkImeb6EduKRzVok/pADoVeNa8XEWAbly+Wipo7qPM4Q=="
	conmanCertificate    = "GAEiBmNvbm1hbhLrAnYyLnB1YmxpYy5RMmR6U1d0TGRqZHpRVmxSTlhJMk0xWkNTVXhEU2k5dU1qVkJVMFZKVEVSME1WRmhRV2huUWtkblNWbENVbTlEUjBGallVRm9aMHRIWjBsM1FWSnZRMGRCU1dGQmFHZEVSMmRKV1VONGIwTkhRWGRoUkZOSlRGcEhWakphVjNoMlkwY3hiR0p1VVdsT1YzTjVURzVDTVZsdGVIQlplVFYzVVRCd2RXSlRNVzlUUjBwd1lUSk5lRmxWY0ZGT2JFWkNUbXRhV1dGc1pESlNibWhIV2pCak1Wa3pXbk5pTTBab1ZIcGFjV1ZyT1VaZ29sMmlPZkRIQ3pNSEF1SFJBM2F5MlRRZVV0SU1ySzN5VHNzVC1HcUM0ekl4a3NFRmVTc0hWbFlTSVlOOTkyd0diY1pyQW0zM1RrOHJ0UFZvWll3Ry5SMEZGYVVKdFRuWmliVEZvWW1kdlJscEhWakpQYWtVOQ=="
)

func generateIntermediateCert(
	parentPrivateKey ed25519.PrivateKey,
	parentAuthority *api.GovalSigningAuthority,
	claims []*api.CertificateClaim,
	issuer string,
	duration time.Duration,
) (ed25519.PrivateKey, *api.GovalSigningAuthority, error) {
	// Generate a new keypair for this cert
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate key pair: %w", err)
	}

	encodedKey := paserk.PublicKeyToPASERKPublic(publicKey)

	cert := &api.GovalCert{
		// Issue this token 15s into the past to accomodate for clock drift.
		Iat:       timestamppb.New(time.Now().Add(-15 * time.Second)),
		Exp:       timestamppb.New(time.Now().Add(duration)),
		Claims:    claims,
		PublicKey: string(encodedKey),
	}

	serializedCert, err := proto.Marshal(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize the cert: %w", err)
	}

	serializedSigningAuth, err := proto.Marshal(parentAuthority)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize the cert: %w", err)
	}

	// Sign the intermediate cert with the parent's cert.
	signedCert, err := paseto.NewV2().Sign(
		parentPrivateKey,
		base64.StdEncoding.EncodeToString(serializedCert),
		base64.StdEncoding.EncodeToString(serializedSigningAuth),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign the cert: %w", err)
	}

	return privateKey, &api.GovalSigningAuthority{
		Cert: &api.GovalSigningAuthority_SignedCert{
			SignedCert: signedCert,
		},
		Issuer:  issuer,
		Version: api.TokenVersion_TYPE_AWARE_TOKEN,
	}, nil
}

// identityToken generates and returns a signed identity (plus a private key)
// for the given repl metadata, both can then be used to sign further identity
// tokens. Other repls can verify this identity to verify a client is a
// particular user or repl.
func identityToken(
	replID string,
	user string,
	userID int64,
	slug string,
) (ed25519.PrivateKey, string, error) {
	return tokenWithClaims(
		replID,
		user,
		userID,
		slug,
		"", // orgId
		0,  // orgType
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
			{Claim: &api.CertificateClaim_Replid{Replid: replID}},
			{Claim: &api.CertificateClaim_User{User: user}},
			{Claim: &api.CertificateClaim_UserId{UserId: userID}},
		},
	)
}

func identityTokenWithOrg(
	replID string,
	user string,
	userID int64,
	slug string,
	orgID string,
	orgType api.Org_OrgType,
) (ed25519.PrivateKey, string, error) {
	return tokenWithClaims(
		replID,
		user,
		userID,
		slug,
		orgID,
		orgType,
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
			{Claim: &api.CertificateClaim_Replid{Replid: replID}},
			{Claim: &api.CertificateClaim_User{User: user}},
			{Claim: &api.CertificateClaim_UserId{UserId: userID}},
			{Claim: &api.CertificateClaim_Org{
				Org: &api.Org{
					Id:   orgID,
					Type: orgType,
				},
			}},
		},
	)
}

func renewalToken(
	replID string,
	user string,
	userID int64,
	slug string,
) (ed25519.PrivateKey, string, error) {
	return tokenWithClaims(
		replID,
		user,
		userID,
		slug,
		"", // orgId
		0,  // orgType
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_RENEW_IDENTITY}},
			{Claim: &api.CertificateClaim_Replid{Replid: replID}},
			{Claim: &api.CertificateClaim_User{User: user}},
			{Claim: &api.CertificateClaim_UserId{UserId: userID}},
		},
	)
}

func tokenWithClaims(
	replID string,
	user string,
	userID int64,
	slug string,
	orgId string,
	orgType api.Org_OrgType,
	claims []*api.CertificateClaim,
) (ed25519.PrivateKey, string, error) {
	replIdentity := api.GovalReplIdentity{
		Replid: replID,
		User:   user,
		UserId: userID,
		Slug:   slug,
		Aud:    replID,
	}

	if orgId != "" {
		replIdentity.Org = &api.Org{
			Id:   orgId,
			Type: orgType,
		}
	}

	var conmanAuthority api.GovalSigningAuthority
	conmanDecodedCertificate, err := base64.StdEncoding.DecodeString(conmanCertificate)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 identity: %w", err)
	}
	err = proto.Unmarshal(conmanDecodedCertificate, &conmanAuthority)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshal identity: %w", err)
	}
	conmanDecodedPrivateKey, err := base64.StdEncoding.DecodeString(conmanPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 private key: %w", err)
	}
	conmanPrivateKey := ed25519.PrivateKey(conmanDecodedPrivateKey)

	intermediatePrivateKey, intermediateAuthority, err := generateIntermediateCert(
		conmanPrivateKey,
		&conmanAuthority,
		claims,
		"conman",
		36*time.Hour, // Repls can not live for more than 20-ish hours at the moment.
	)
	if err != nil {
		return nil, "", fmt.Errorf("generate intermediate identity cert: %w", err)
	}

	token, err := signIdentity(intermediatePrivateKey, intermediateAuthority, &replIdentity)
	if err != nil {
		return nil, "", fmt.Errorf("sign identity: %w", err)
	}

	return intermediatePrivateKey, token, nil
}

// identityToken generates and returns a signed identity (plus a private key)
// for the given repl metadata with a specific origin ID.
func identityTokenWithOrigin(
	replID string,
	user string,
	userID int64,
	slug string,
	originID string,
) (ed25519.PrivateKey, string, error) {
	replIdentity := api.GovalReplIdentity{
		Replid:       replID,
		User:         user,
		UserId:       userID,
		Slug:         slug,
		Aud:          replID,
		OriginReplid: originID,
	}

	var conmanAuthority api.GovalSigningAuthority
	conmanDecodedCertificate, err := base64.StdEncoding.DecodeString(conmanCertificate)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 identity: %w", err)
	}
	err = proto.Unmarshal(conmanDecodedCertificate, &conmanAuthority)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshal identity: %w", err)
	}
	conmanDecodedPrivateKey, err := base64.StdEncoding.DecodeString(conmanPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 private key: %w", err)
	}
	conmanPrivateKey := ed25519.PrivateKey(conmanDecodedPrivateKey)

	intermediatePrivateKey, intermediateAuthority, err := generateIntermediateCert(
		conmanPrivateKey,
		&conmanAuthority,
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
			{Claim: &api.CertificateClaim_Replid{Replid: replIdentity.Replid}},
			{Claim: &api.CertificateClaim_User{User: replIdentity.User}},
			{Claim: &api.CertificateClaim_UserId{UserId: replIdentity.UserId}},
		},
		"conman",
		36*time.Hour, // Repls can not live for more than 20-ish hours at the moment.
	)
	if err != nil {
		return nil, "", fmt.Errorf("generate intermediate identity cert: %w", err)
	}

	token, err := signIdentity(intermediatePrivateKey, intermediateAuthority, &replIdentity)
	if err != nil {
		return nil, "", fmt.Errorf("sign identity: %w", err)
	}

	return intermediatePrivateKey, token, nil
}

// identityTokenAnyRepl creates an identity token that allows for any replid
func identityTokenAnyRepl(
	replID string,
	user string,
	userID int64,
	slug string,
) (ed25519.PrivateKey, string, error) {
	replIdentity := api.GovalReplIdentity{
		Replid: replID,
		User:   user,
		UserId: userID,
		Slug:   slug,
		Aud:    replID,
	}

	var conmanAuthority api.GovalSigningAuthority
	conmanDecodedCertificate, err := base64.StdEncoding.DecodeString(conmanCertificate)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 identity: %w", err)
	}
	err = proto.Unmarshal(conmanDecodedCertificate, &conmanAuthority)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshal identity: %w", err)
	}
	conmanDecodedPrivateKey, err := base64.StdEncoding.DecodeString(conmanPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 private key: %w", err)
	}
	conmanPrivateKey := ed25519.PrivateKey(conmanDecodedPrivateKey)

	intermediatePrivateKey, intermediateAuthority, err := generateIntermediateCert(
		conmanPrivateKey,
		&conmanAuthority,
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_RENEW_IDENTITY}},
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_ANY_REPLID}},
			{Claim: &api.CertificateClaim_Cluster{Cluster: "development"}},
			{Claim: &api.CertificateClaim_User{User: replIdentity.User}},
			{Claim: &api.CertificateClaim_UserId{UserId: replIdentity.UserId}},
		},
		"conman",
		36*time.Hour, // Repls can not live for more than 20-ish hours at the moment.
	)
	if err != nil {
		return nil, "", fmt.Errorf("generate intermediate identity cert: %w", err)
	}

	token, err := signIdentity(intermediatePrivateKey, intermediateAuthority, &replIdentity)
	if err != nil {
		return nil, "", fmt.Errorf("sign identity: %w", err)
	}

	return intermediatePrivateKey, token, nil
}

// multiTierIdentityToken generates and returns a broken identity token that includes
// intermediate certs with differing repl IDs.
func multiTierIdentityToken(
	replID string,
	user string,
	userID int64,
	slug string,
) (ed25519.PrivateKey, string, error) {
	replIdentity := api.GovalReplIdentity{
		Replid: replID,
		User:   user,
		UserId: userID,
		Slug:   slug,
		Aud:    replID,
	}

	var conmanAuthority api.GovalSigningAuthority
	conmanDecodedCertificate, err := base64.StdEncoding.DecodeString(conmanCertificate)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 identity: %w", err)
	}
	err = proto.Unmarshal(conmanDecodedCertificate, &conmanAuthority)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshal identity: %w", err)
	}
	conmanDecodedPrivateKey, err := base64.StdEncoding.DecodeString(conmanPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 private key: %w", err)
	}
	conmanPrivateKey := ed25519.PrivateKey(conmanDecodedPrivateKey)

	intermediatePrivateKey, intermediateAuthority, err := generateIntermediateCert(
		conmanPrivateKey,
		&conmanAuthority,
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
			{Claim: &api.CertificateClaim_Replid{Replid: replIdentity.Replid}},
			{Claim: &api.CertificateClaim_User{User: replIdentity.User}},
			{Claim: &api.CertificateClaim_UserId{UserId: replIdentity.UserId}},
		},
		"conman",
		36*time.Hour, // Repls can not live for more than 20-ish hours at the moment.
	)
	if err != nil {
		return nil, "", fmt.Errorf("generate intermediate identity cert: %w", err)
	}

	finalPrivateKey, finalAuthority, err := generateIntermediateCert(
		intermediatePrivateKey,
		intermediateAuthority,
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
			{Claim: &api.CertificateClaim_Replid{Replid: replIdentity.Replid + "-spoofed"}},
			{Claim: &api.CertificateClaim_User{User: replIdentity.User}},
			{Claim: &api.CertificateClaim_UserId{UserId: replIdentity.UserId}},
		},
		"conman",
		36*time.Hour, // Repls can not live for more than 20-ish hours at the moment.
	)
	if err != nil {
		return nil, "", fmt.Errorf("generate intermediate identity cert: %w", err)
	}

	token, err := signIdentity(finalPrivateKey, finalAuthority, &replIdentity)
	if err != nil {
		return nil, "", fmt.Errorf("sign identity: %w", err)
	}

	return finalPrivateKey, token, nil
}

func TestIdentity(t *testing.T) {
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

	replIdentity, err := VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
	)
	require.NoError(t, err)

	// identities without origin repl IDs are accepted by default
	// (they're not guest forks, replID can be used)
	_, err = VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
		WithSource("origin"),
	)
	require.NoError(t, err)

	assert.Equal(t, "repl", replIdentity.Replid)
	assert.Equal(t, "user", replIdentity.User)
	assert.Equal(t, int64(1), replIdentity.UserId)
	assert.Equal(t, "slug", replIdentity.Slug)
}

func TestNoIdentityClaim(t *testing.T) {
	replID := "repl"
	user := "user"
	privkey, identity, err := tokenWithClaims(
		replID,
		user,
		1,
		"slug",
		"",
		0,
		// We're leaving out the IDENTITY claim
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_User{User: user}},
			{Claim: &api.CertificateClaim_UserId{UserId: 1}},
			{Claim: &api.CertificateClaim_Replid{Replid: replID}},
		})
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

	_, err = VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
	)
	// Check that we got a 'token not authorized for flag IDENTITY' error
	require.Error(t, err)
	assert.Equal(t, "token not authorized for flag IDENTITY", err.Error())
}

func TestOriginIdentity(t *testing.T) {
	privkey, identity, err := identityTokenWithOrigin("repl", "user", 1, "slug", "origin")
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

	replIdentity, err := VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
		WithSource("origin"),
	)
	require.NoError(t, err)

	_, err = VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
		WithSource("another-origin"),
	)
	require.Error(t, err)

	assert.Equal(t, "repl", replIdentity.Replid)
	assert.Equal(t, "user", replIdentity.User)
	assert.Equal(t, int64(1), replIdentity.UserId)
	assert.Equal(t, "slug", replIdentity.Slug)
	assert.Equal(t, "origin", replIdentity.OriginReplid)
}

func TestLayeredIdentity(t *testing.T) {
	layeredReplIdentity := api.GovalReplIdentity{
		Replid: "a-b-c-d",
		User:   "spoof",
		UserId: 2,
		Slug:   "spoofed",
		Aud:    "another-audience",
	}

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

	// generate yet another layer using our key
	token, err := signIdentity(privkey, signingAuthority.signingAuthority, &layeredReplIdentity)
	require.NoError(t, err)

	_, err = VerifyIdentity(
		token,
		// the audience claim mismatch fails too early. we need to make sure we don't trust
		// the wrong level of replid/user/slug, because another repl could use its private
		// key to sign a spoofed identity with a "valid" audience.
		[]string{"another-audience"},
		getPubKey,
	)
	require.Error(t, err)
}

func TestLayeredIdentityWithSpoofedCert(t *testing.T) {
	privkey, identity, err := multiTierIdentityToken("repl", "user", 1, "slug")
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

	// This will fail (extra intermediate cert is not permitted)
	_, err = NewSigningAuthority(
		string(paserk.PrivateKeyToPASERKSecret(privkey)),
		identity,
		"repl",
		getPubKey,
	)
	require.Error(t, err)
}

func TestAnyReplIDIdentity(t *testing.T) {
	layeredReplIdentity := api.GovalReplIdentity{
		Replid: "a-b-c-d",
		User:   "user",
		UserId: 1,
		Slug:   "slug",
		Aud:    "another-audience",
		Runtime: &api.GovalReplIdentity_Interactive{
			Interactive: &api.ReplRuntimeInteractive{
				Cluster:    "development",
				Subcluster: "",
			},
		},
	}

	privkey, identity, err := identityTokenAnyRepl("repl", "user", 1, "slug")
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

	// generate yet another layer using our key
	token, err := signIdentity(privkey, signingAuthority.signingAuthority, &layeredReplIdentity)
	require.NoError(t, err)

	replIdentity, err := VerifyIdentity(
		token,
		[]string{"another-audience"},
		getPubKey,
	)
	require.NoError(t, err)

	assert.Equal(t, "a-b-c-d", replIdentity.Replid)
	assert.Equal(t, "user", replIdentity.User)
	assert.Equal(t, int64(1), replIdentity.UserId)
	assert.Equal(t, "slug", replIdentity.Slug)
}

func TestSpoofedRuntimeIdentity(t *testing.T) {
	for i, layeredReplIdentity := range []*api.GovalReplIdentity{
		{
			Replid: "a-b-c-d",
			User:   "user",
			UserId: 1,
			Slug:   "slug",
			Aud:    "another-audience",
			Runtime: &api.GovalReplIdentity_Interactive{
				Interactive: &api.ReplRuntimeInteractive{
					Cluster:    "development",
					Subcluster: "foo",
				},
			},
		},
		{
			Replid: "a-b-c-d",
			User:   "user",
			UserId: 1,
			Slug:   "slug",
			Aud:    "another-audience",
			Runtime: &api.GovalReplIdentity_Hosting{
				Hosting: &api.ReplRuntimeHosting{
					Cluster:    "development",
					Subcluster: "foo",
				},
			},
		},
		{
			Replid: "a-b-c-d",
			User:   "user",
			UserId: 1,
			Slug:   "slug",
			Aud:    "another-audience",
			Runtime: &api.GovalReplIdentity_Deployment{
				Deployment: &api.ReplRuntimeDeployment{},
			},
		},
	} {
		layeredReplIdentity := layeredReplIdentity
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			privkey, identity, err := identityTokenAnyRepl("repl", "user", 1, "slug")
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

			// generate yet another layer using our key
			token, err := signIdentity(privkey, signingAuthority.signingAuthority, layeredReplIdentity)
			require.NoError(t, err)

			_, err = VerifyIdentity(
				token,
				[]string{"another-audience"},
				getPubKey,
			)
			assert.Error(t, err)
		})
	}
}

func TestRenew(t *testing.T) {
	privkey, identity, err := renewalToken("repl", "user", 1, "slug")
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

	replIdentity, err := VerifyRenewIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
	)
	require.NoError(t, err)

	assert.Equal(t, "repl", replIdentity.Replid)
	assert.Equal(t, "user", replIdentity.User)
	assert.Equal(t, int64(1), replIdentity.UserId)
	assert.Equal(t, "slug", replIdentity.Slug)
}

func TestRenewNoClaim(t *testing.T) {
	privkey, identity, err := tokenWithClaims(
		"replid",
		"user",
		1,
		"slug",
		"", // org Id
		0,  // org type
		[]*api.CertificateClaim{
			{Claim: &api.CertificateClaim_Replid{Replid: "replid"}},
			{Claim: &api.CertificateClaim_User{User: "user"}},
		},
	)
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
		"replid",
		getPubKey,
	)
	require.NoError(t, err)
	forwarded, err := signingAuthority.Sign("testing")
	require.NoError(t, err)

	_, err = VerifyRenewIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
	)
	require.Error(t, err)
}

func TestIdentityWithOrgID(t *testing.T) {
	privkey, identity, err := identityTokenWithOrg("repl", "user", 1, "slug", "acmecorp", api.Org_TEAM)
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

	replIdentity, err := VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
	)
	require.NoError(t, err)

	// identities without origin repl IDs are accepted by default
	// (they're not guest forks, replID can be used)
	_, err = VerifyIdentity(
		forwarded,
		[]string{"testing"},
		getPubKey,
		WithSource("origin"),
	)
	require.NoError(t, err)

	assert.Equal(t, "repl", replIdentity.Replid)
	assert.Equal(t, "user", replIdentity.User)
	assert.Equal(t, int64(1), replIdentity.UserId)
	assert.Equal(t, "slug", replIdentity.Slug)
	assert.Equal(t, "acmecorp", replIdentity.Org.Id)
}

func TestIdentityWithOrgIDFail(t *testing.T) {
	replID := "repl"
	user := "user"
	var userID int64 = 1
	slug := "slug"
	orgID := "acmecorp"
	orgType := api.Org_PERSONAL

	tcs := []struct {
		name   string
		claims []*api.CertificateClaim
	}{
		{
			name: "missing org claim",
			claims: []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Replid{Replid: "repl"}},
				{Claim: &api.CertificateClaim_User{User: "user"}},
				{Claim: &api.CertificateClaim_UserId{UserId: 1}},
			},
		},
		{
			name: "org id mismatch",
			claims: []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Replid{Replid: "repl"}},
				{Claim: &api.CertificateClaim_User{User: "user"}},
				{Claim: &api.CertificateClaim_UserId{UserId: 1}},
				{Claim: &api.CertificateClaim_Org{
					Org: &api.Org{
						Id:   "wrong-org-id",
						Type: orgType,
					}},
				},
			},
		},
		{
			name: "org type mismatch",
			claims: []*api.CertificateClaim{
				{Claim: &api.CertificateClaim_Flag{Flag: api.FlagClaim_IDENTITY}},
				{Claim: &api.CertificateClaim_Replid{Replid: "repl"}},
				{Claim: &api.CertificateClaim_User{User: "user"}},
				{Claim: &api.CertificateClaim_UserId{UserId: 1}},
				{Claim: &api.CertificateClaim_Org{
					Org: &api.Org{
						Id:   orgID,
						Type: orgType + 1,
					}},
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			identity := api.GovalReplIdentity{
				Replid: replID,
				User:   user,
				UserId: userID,
				Slug:   slug,
				Aud:    replID,
				Org: &api.Org{
					Id:   orgID,
					Type: orgType,
				},
			}

			privkey, marshaledIdentity, err := tokenWithClaims(
				replID,
				user,
				userID,
				slug,
				orgID,
				orgType,
				tc.claims,
			)
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

			_, err = NewSigningAuthority(
				string(paserk.PrivateKeyToPASERKSecret(privkey)),
				marshaledIdentity,
				"repl",
				getPubKey,
			)
			require.Error(t, err)
			assert.Equal(t, "claim mismatch: not authorized (orgId)", err.Error())

			// check that, if we were to sign the token, the
			// receiving party would also not be able to verify it
			sa, err := getSigningAuthority(marshaledIdentity)
			require.NoError(t, err)

			signingAuthority := &SigningAuthority{
				privateKey:       privkey,
				signingAuthority: sa,
				identity:         &identity,
			}

			forwarded, err := signingAuthority.Sign("testing")
			require.NoError(t, err)

			_, err = VerifyIdentity(
				forwarded,
				[]string{"testing"},
				getPubKey,
			)
			require.Error(t, err)
			assert.Equal(t, "claim mismatch: not authorized (orgId)", err.Error())
		})
	}
}
