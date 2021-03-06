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

	"github.com/replit/go-replidentity/api"
	"github.com/replit/go-replidentity/paserk"
)

const (
	developmentKeyID     = "dev:1"
	developmentPublicKey = "on0FkSmEC+ce40V9Vc4QABXSx6TXo+lhp99b6Ka0gro="
	conmanPrivateKey     = "jF/ctKF4x9mL+s8e8bLe2R0Dmzr4FQ+hwBIm6U7TuBRrujSaTKHTWbXSoUc2Y0uQ3mm2YqOmQeR/isCd0qJrVw=="
	conmanCertificate    = "GAEiBmNvbm1hbhK7AnYyLnB1YmxpYy5RMmQzU1hoMUsyZHNaMWxSZFdVM2NXNVJSVk5FUVdwV01YRlhiRUpvUkdRclpYRmtRVkp2UTBkQlJXRkJhR2RHUjJkSldVRm9iME5IUVUxaFFXaG5SVWxxVm5KTmFUVjNaRmRLYzJGWFRYVlpWR1IyVFVjeGNtVlhaM2ROVnpCNFRVaEdSMU5GTlhSVWEzaHlWR3BXZDJSSE1VeGhia0p5VTBkMGJVNUlTa0ppYlZKTVlWZEZlRmwzUFQxX1g4OVJiVDhTQlhLUUVpVzZfLXBFYUtUX2l1T3lnalB1QVhxajRZSDNHT1FiRlVSY08ydTRFZWF2SUJWU09oRHV4VF82NHFwZG4ydWkxcGo2RjRzTy5SMEZGYVVKdFRuWmliVEZvWW1kdlJscEhWakpQYWtVOQ=="
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
	slug string,
) (ed25519.PrivateKey, string, error) {
	replIdentity := api.GovalReplIdentity{
		Replid: replID,
		User:   user,
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

func TestIdentity(t *testing.T) {
	privkey, identity, err := identityToken("repl", "user", "slug")
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
		"testing",
		getPubKey,
	)
	require.NoError(t, err)

	assert.Equal(t, "repl", replIdentity.Replid)
	assert.Equal(t, "user", replIdentity.User)
	assert.Equal(t, "slug", replIdentity.Slug)
}
