package replidentity

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/o1egl/paseto"
	"github.com/replit/go-replidentity/api"
	"github.com/replit/go-replidentity/paserk"
	"google.golang.org/protobuf/proto"
)

// SigningAuthority can generate tokens that prove the identity of one repl
// (your own) against another repl (the audience). Use this to prevent the
// target repl from spoofing your own identity by forwarding the token.
type SigningAuthority struct {
	privateKey       ed25519.PrivateKey
	signingAuthority *api.GovalSigningAuthority
	identity         *api.GovalReplIdentity
}

// NewSigningAuthority returns a new SigningAuthority given the marshaled
// private key (obtained from the `REPL_IDENTITY_KEY` environment variable),
// the identity token (obtained from the `REPL_IDENTITY` environment variable),
// the current Repl ID (obtained from the `REPL_ID` environment varaible), and
// the source of public keys (typically [ReadPublicKeyFromEnv]).
func NewSigningAuthority(
	marshaledPrivateKey,
	marshaledIdentity string,
	replid string,
	getPubKey PubKeySource,
) (*SigningAuthority, error) {
	bytes, _, err := verifyChain(marshaledIdentity, getPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed verify message: %w", err)
	}
	signingAuthority, err := getSigningAuthority(marshaledIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to read body type: %w", err)
	}
	privateKey, err := paserk.PASERKSecretToPrivateKey(paserk.PASERKSecret(marshaledPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	var identity api.GovalReplIdentity

	switch signingAuthority.GetVersion() {
	case api.TokenVersion_BARE_REPL_TOKEN:
		return nil, errors.New("wrong type of token provided")
	case api.TokenVersion_TYPE_AWARE_TOKEN:
		err = proto.Unmarshal(bytes, &identity)
		if err != nil {
			return nil, fmt.Errorf("failed to decode body: %w", err)
		}
	}

	if replid != identity.Replid {
		return nil, fmt.Errorf("message replid mismatch. expected %q, got %q", replid, identity.Replid)
	}
	if replid != identity.Aud {
		return nil, fmt.Errorf("message audience mismatch. expected %q, got %q", replid, identity.Aud)
	}

	return &SigningAuthority{
		privateKey:       privateKey,
		signingAuthority: signingAuthority,
		identity:         &identity,
	}, nil
}

// Sign generates a new token that can be given to the provided audience, and
// is resistant against forwarding, so that the recipient cannot forward this
// token to another repl and claim it came directly from you.
func (a *SigningAuthority) Sign(audience string) (string, error) {
	replIdentity := api.GovalReplIdentity{
		Replid: a.identity.Replid,
		User:   a.identity.User,
		Slug:   a.identity.Slug,
		Aud:    audience,
	}

	token, err := signIdentity(a.privateKey, a.signingAuthority, &replIdentity)
	if err != nil {
		return "", fmt.Errorf("sign identity: %w", err)
	}

	return token, nil
}

func signIdentity(
	parentPrivateKey ed25519.PrivateKey,
	parentAuthority *api.GovalSigningAuthority,
	identity *api.GovalReplIdentity,
) (string, error) {
	encodedIdentity, err := proto.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("failed to serialize the identity: %w", err)
	}

	serializedCert, err := proto.Marshal(parentAuthority)

	if err != nil {
		return "", fmt.Errorf("failed to serialize the cert: %w", err)
	}

	return paseto.NewV2().Sign(
		parentPrivateKey,
		base64.StdEncoding.EncodeToString(encodedIdentity),
		base64.StdEncoding.EncodeToString(serializedCert),
	)
}
