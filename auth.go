// Package replidentity provides verification utilities for Repl Identity tokens.
package replidentity

import (
	"encoding/base64"
	"fmt"

	"github.com/o1egl/paseto"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"

	"github.com/replit/go-replidentity/protos/external/goval/api"
)

// PubKeySource provides an interface for looking up an [ed25519.PublicKey] from some external source.
type PubKeySource func(keyid, issuer string) (ed25519.PublicKey, error)

// MessageClaims is a collection of indexable claims that are made by a certificate.
type MessageClaims struct {
	Repls       map[string]struct{}
	Users       map[string]struct{}
	UserIDs     map[int64]struct{}
	Clusters    map[string]struct{}
	Subclusters map[string]struct{}
	Flags       map[api.FlagClaim]struct{}
}

func parseClaims(cert *api.GovalCert) *MessageClaims {
	if cert == nil {
		return nil
	}

	claims := MessageClaims{
		Repls:       map[string]struct{}{},
		Users:       map[string]struct{}{},
		UserIDs:     map[int64]struct{}{},
		Clusters:    map[string]struct{}{},
		Subclusters: map[string]struct{}{},
		Flags:       map[api.FlagClaim]struct{}{},
	}

	for _, claim := range cert.Claims {
		switch typedClaim := claim.Claim.(type) {
		case *api.CertificateClaim_Replid:
			claims.Repls[typedClaim.Replid] = struct{}{}

		case *api.CertificateClaim_User:
			claims.Users[typedClaim.User] = struct{}{}

		case *api.CertificateClaim_UserId:
			claims.UserIDs[typedClaim.UserId] = struct{}{}

		case *api.CertificateClaim_Cluster:
			claims.Clusters[typedClaim.Cluster] = struct{}{}

		case *api.CertificateClaim_Subcluster:
			claims.Subclusters[typedClaim.Subcluster] = struct{}{}

		case *api.CertificateClaim_Flag:
			claims.Flags[typedClaim.Flag] = struct{}{}
		}
	}

	return &claims
}

func getSigningAuthority(message string) (*api.GovalSigningAuthority, error) {
	var encodedFooter string
	err := paseto.ParseFooter(message, &encodedFooter)
	if err != nil {
		return nil, err
	}

	if len(encodedFooter) == 0 {
		return nil, fmt.Errorf("footer is empty")
	}

	footerBytes, err := base64.StdEncoding.DecodeString(encodedFooter)
	if err != nil {
		return nil, fmt.Errorf("failed to decode footer: %w", err)
	}

	var signingAuthority api.GovalSigningAuthority
	err = proto.Unmarshal(footerBytes, &signingAuthority)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal footer: %w", err)
	}

	return &signingAuthority, nil
}
