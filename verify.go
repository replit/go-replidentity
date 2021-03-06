package replidentity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/o1egl/paseto"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"

	"github.com/replit/go-replidentity/api"
	"github.com/replit/go-replidentity/paserk"
)

func verifyToken(token string, pubkey ed25519.PublicKey) ([]byte, error) {
	var meta string

	err := paseto.NewV2().Verify(token, pubkey, &meta, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token with public key: %w", err)
	}

	bytes, err := base64.StdEncoding.DecodeString(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return bytes, nil
}

func verifyTokenWithKeyID(token string, keyid string, issuer string, getPubKey PubKeySource) ([]byte, error) {
	pubkey, err := getPubKey(keyid, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get pubkey %s: %w", keyid, err)
	}

	return verifyToken(token, pubkey)
}

func verifyTokenWithCert(token string, cert *api.GovalCert) ([]byte, error) {
	var pubkey ed25519.PublicKey
	var err error

	if strings.HasPrefix(cert.PublicKey, paserk.PaserkPublicHeader) {
		pubkey, err = paserk.PASERKPublicToPublicKey(paserk.PASERKPublic(cert.PublicKey))
	} else {
		pubkey, err = pemToPubkey(cert.PublicKey)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return verifyToken(token, pubkey)
}

func verifyCert(certBytes []byte, signingCert *api.GovalCert) (*api.GovalCert, error) {
	var cert api.GovalCert
	err := proto.Unmarshal(certBytes, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cert: %w", err)
	}

	// Verify that the cert is valid
	err = verifyClaims(cert.Iat.AsTime(), cert.Exp.AsTime(), "", nil)
	if err != nil {
		return nil, fmt.Errorf("cert is not valid: %w", err)
	}

	// If the parent cert is not the root cert
	if signingCert != nil {
		claims := parseClaims(signingCert)
		if _, ok := claims.Flags[api.FlagClaim_SIGN_INTERMEDIATE_CERT]; !ok {
			return nil, fmt.Errorf("signing cert doesn't have authority to sign intermediate certs")

		}

		// Verify the cert claims agrees with its signer
		authorizedClaims := map[string]struct{}{}
		var anyReplid, anyUser, anyCluster bool
		for _, claim := range signingCert.Claims {
			authorizedClaims[claim.String()] = struct{}{}
			switch tc := claim.Claim.(type) {
			case *api.CertificateClaim_Flag:
				if tc.Flag == api.FlagClaim_ANY_REPLID {
					anyReplid = true
				}
				if tc.Flag == api.FlagClaim_ANY_USER {
					anyUser = true
				}
				if tc.Flag == api.FlagClaim_ANY_CLUSTER {
					anyCluster = true
				}
			}
		}

		for _, claim := range cert.Claims {
			switch claim.Claim.(type) {
			case *api.CertificateClaim_Replid:
				if anyReplid {
					continue
				}
			case *api.CertificateClaim_User:
				if anyUser {
					continue
				}
			case *api.CertificateClaim_Cluster:
				if anyCluster {
					continue
				}
			}
			if _, ok := authorizedClaims[claim.String()]; !ok {
				return nil, fmt.Errorf("signing cert does not authorize claim: %s", claim)
			}
		}
	}

	return &cert, nil
}

func verifyChain(token string, getPubKey PubKeySource) ([]byte, *api.GovalCert, error) {
	signingAuthority, err := getSigningAuthority(token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get authority: %w", err)
	}

	switch signingAuth := signingAuthority.Cert.(type) {
	case *api.GovalSigningAuthority_KeyId:
		// If it's signed directly with a root key, grab the pubkey and verify it
		verifiedBytes, err := verifyTokenWithKeyID(token, signingAuth.KeyId, signingAuthority.Issuer, getPubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify root signiture: %w", err)
		}

		return verifiedBytes, nil, nil

	case *api.GovalSigningAuthority_SignedCert:
		// If its signed by another token, verify the other token first
		signingBytes, skipLevelCert, err := verifyChain(signingAuth.SignedCert, getPubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify signing token: %w", err)
		}

		// Make sure the two parent certs agree
		signingCert, err := verifyCert(signingBytes, skipLevelCert)
		if err != nil {
			return nil, nil, fmt.Errorf("signing cert invalid: %w", err)
		}

		// Now verify this token using the parent cert
		verifiedBytes, err := verifyTokenWithCert(token, signingCert)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify token: %w", err)
		}

		return verifiedBytes, signingCert, nil

	default:
		return nil, nil, fmt.Errorf("unknown token authority: %s", signingAuth)
	}
}

// VerifyIdentity verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient).
func VerifyIdentity(message string, audience string, getPubKey PubKeySource) (*api.GovalReplIdentity, error) {
	bytes, _, err := verifyChain(message, getPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed verify message: %w", err)
	}

	signingAuthority, err := getSigningAuthority(message)
	if err != nil {
		return nil, fmt.Errorf("failed to read body type: %w", err)
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

	if audience != identity.Aud {
		return nil, fmt.Errorf("message identity mismatch. expected %q, got %q", audience, identity.Aud)
	}

	// TODO(miselin): need to check claims? and authority expiry?
	return &identity, nil
}

func verifyClaims(iat time.Time, exp time.Time, replid string, claims *MessageClaims) error {
	if iat.After(time.Now()) {
		return fmt.Errorf("not valid for %s", time.Until(iat))
	}

	if exp.Before(time.Now()) {
		return fmt.Errorf("expired %s ago", time.Since(exp))
	}

	if claims != nil {
		authorized := false

		if _, ok := claims.Repls[replid]; ok {
			authorized = true
		}

		if !authorized {
			return errors.New("not authorized")
		}
	}

	return nil
}
