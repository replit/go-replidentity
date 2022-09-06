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

type verifier struct {
	claims *MessageClaims

	// signing certs can allow "any *" variants
	anyReplid  bool
	anyUser    bool
	anyCluster bool
}

func (v *verifier) verifyToken(token string, pubkey ed25519.PublicKey) ([]byte, error) {
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

func (v *verifier) verifyTokenWithKeyID(token string, keyid string, issuer string, getPubKey PubKeySource) ([]byte, error) {
	pubkey, err := getPubKey(keyid, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get pubkey %s: %w", keyid, err)
	}

	return v.verifyToken(token, pubkey)
}

func (v *verifier) verifyTokenWithCert(token string, cert *api.GovalCert) ([]byte, error) {
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

	return v.verifyToken(token, pubkey)
}

func (v *verifier) verifyCert(certBytes []byte, signingCert *api.GovalCert) (*api.GovalCert, error) {
	var cert api.GovalCert
	err := proto.Unmarshal(certBytes, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cert: %w", err)
	}

	// Verify that the cert is valid
	err = verifyClaims(cert.Iat.AsTime(), cert.Exp.AsTime(), "", "", "", nil)
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
			switch tc := claim.Claim.(type) {
			case *api.CertificateClaim_Flag:
				v.anyReplid = tc.Flag == api.FlagClaim_ANY_REPLID
				v.anyUser = tc.Flag == api.FlagClaim_ANY_USER
				v.anyCluster = tc.Flag == api.FlagClaim_ANY_CLUSTER
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

	// Store this cert's claims so we can validate tokens later.
	certClaims := parseClaims(&cert)
	if certClaims != nil {
		v.claims = certClaims
	}

	return &cert, nil
}

func (v *verifier) verifyChain(token string, getPubKey PubKeySource) ([]byte, *api.GovalCert, error) {
	signingAuthority, err := getSigningAuthority(token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get authority: %w", err)
	}

	switch signingAuth := signingAuthority.Cert.(type) {
	case *api.GovalSigningAuthority_KeyId:
		// If it's signed directly with a root key, grab the pubkey and verify it
		verifiedBytes, err := v.verifyTokenWithKeyID(token, signingAuth.KeyId, signingAuthority.Issuer, getPubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify root signiture: %w", err)
		}

		return verifiedBytes, nil, nil

	case *api.GovalSigningAuthority_SignedCert:
		// If its signed by another token, verify the other token first
		signingBytes, skipLevelCert, err := v.verifyChain(signingAuth.SignedCert, getPubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify signing token: %w", err)
		}

		// Make sure the two parent certs agree
		signingCert, err := v.verifyCert(signingBytes, skipLevelCert)
		if err != nil {
			return nil, nil, fmt.Errorf("signing cert invalid: %w", err)
		}

		// Now verify this token using the parent cert
		verifiedBytes, err := v.verifyTokenWithCert(token, signingCert)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify token: %w", err)
		}

		return verifiedBytes, signingCert, nil

	default:
		return nil, nil, fmt.Errorf("unknown token authority: %s", signingAuth)
	}
}

// easy entry-point so you don't need to create a verifier yourself
func verifyChain(token string, getPubKey PubKeySource) (*verifier, []byte, *api.GovalCert, error) {
	v := verifier{}
	bytes, cert, err := v.verifyChain(token, getPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return &v, bytes, cert, err
}

// checkClaimsAgainstToken ensures the claims match up with the token.
// This ensures that the final token in the chain is not spoofed via the forwarding protection private key.
func (v *verifier) checkClaimsAgainstToken(token *api.GovalReplIdentity) error {
	// if the claims are nil, it means that the token was signed by the root privkey,
	// which implicitly has all claims.
	if v.claims == nil {
		return nil
	}

	return verifyRawClaims(token.Replid, token.User, "", v.claims, v.anyReplid, v.anyUser, v.anyCluster)
}

// VerifyIdentity verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient).
func VerifyIdentity(message string, audience string, getPubKey PubKeySource) (*api.GovalReplIdentity, error) {
	v, bytes, _, err := verifyChain(message, getPubKey)
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

	err = v.checkClaimsAgainstToken(&identity)
	if err != nil {
		return nil, fmt.Errorf("claim mismatch: %w", err)
	}

	return &identity, nil
}

// VerifyIdentityWithSource verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient). It also verifies that the identity's origin replID
// matches the given source, if present. This can be used to enforce specific clients
// in servers when verifying identities.
func VerifyIdentityWithSource(message string, audience string, sourceReplid string, getPubKey PubKeySource) (*api.GovalReplIdentity, error) {
	identity, err := VerifyIdentity(message, audience, getPubKey)
	if err != nil {
		return nil, err
	}

	if identity.OriginReplid != "" && identity.OriginReplid != sourceReplid {
		return nil, errors.New("identity origin replid does not match")
	}

	return identity, nil
}

func verifyRawClaims(replid, user, cluster string, claims *MessageClaims, anyReplid, anyUser, anyCluster bool) error {
	if claims != nil {
		if replid != "" && !anyReplid {
			if _, ok := claims.Repls[replid]; !ok {
				return errors.New("not authorized (replid)")
			}
		}

		if user != "" && !anyUser {
			if _, ok := claims.Users[user]; !ok {
				return errors.New("not authorized (user)")
			}
		}

		if cluster != "" && !anyCluster {
			if _, ok := claims.Clusters[cluster]; !ok {
				return errors.New("not authorized (cluster)")
			}
		}
	}

	return nil
}

func verifyClaims(iat time.Time, exp time.Time, replid, user, cluster string, claims *MessageClaims) error {
	if iat.After(time.Now()) {
		return fmt.Errorf("not valid for %s", time.Until(iat))
	}

	if exp.Before(time.Now()) {
		return fmt.Errorf("expired %s ago", time.Since(exp))
	}

	return verifyRawClaims(replid, user, cluster, claims, false, false, false)
}
