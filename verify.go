package replidentity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/o1egl/paseto"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/replit/go-replidentity/paserk"
	"github.com/replit/go-replidentity/protos/external/goval/api"
)

type verifier struct {
	claims *MessageClaims

	// signing certs can allow "any *" variants
	anyReplid     bool
	anyUser       bool
	anyUserID     bool
	anyCluster    bool
	anySubcluster bool
	deployments   bool
}

func (v *verifier) verifyToken(token string, pubkey ed25519.PublicKey) ([]byte, error) {
	if len(pubkey) == 0 {
		return nil, errors.New("pubkey is empty")
	}

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
	err = verifyClaims(cert.Iat.AsTime(), cert.Exp.AsTime(), "", "", "", "", false, nil)
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
		var anyReplid, anyUser, anyUserID, anyCluster, anySubcluster, deployments bool
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
				if tc.Flag == api.FlagClaim_ANY_USER_ID {
					anyUserID = true
				}
				if tc.Flag == api.FlagClaim_ANY_CLUSTER {
					anyCluster = true
				}
				if tc.Flag == api.FlagClaim_ANY_SUBCLUSTER {
					anySubcluster = true
				}
				if tc.Flag == api.FlagClaim_DEPLOYMENTS {
					deployments = true
				}
			}
		}

		for _, claim := range cert.Claims {
			switch tc := claim.Claim.(type) {
			case *api.CertificateClaim_Flag:
				if tc.Flag == api.FlagClaim_ANY_REPLID {
					v.anyReplid = true
				}
				if tc.Flag == api.FlagClaim_ANY_USER {
					v.anyUser = true
				}
				if tc.Flag == api.FlagClaim_ANY_USER_ID {
					v.anyUserID = true
				}
				if tc.Flag == api.FlagClaim_ANY_CLUSTER {
					v.anyCluster = true
				}
				if tc.Flag == api.FlagClaim_ANY_SUBCLUSTER {
					v.anySubcluster = true
				}
				if tc.Flag == api.FlagClaim_DEPLOYMENTS {
					v.deployments = true
				}
			case *api.CertificateClaim_Replid:
				if anyReplid {
					continue
				}
			case *api.CertificateClaim_User:
				if anyUser {
					continue
				}
			case *api.CertificateClaim_UserId:
				if anyUserID {
					continue
				}
			case *api.CertificateClaim_Cluster:
				if anyCluster {
					continue
				}
			case *api.CertificateClaim_Subcluster:
				if anySubcluster {
					continue
				}
			case *api.CertificateClaim_Deployment:
				if deployments || !tc.Deployment {
					continue
				}
			}
			if _, ok := authorizedClaims[claim.String()]; !ok {
				return nil, fmt.Errorf("signing cert {%+v} does not authorize claim in {%+v}: %s", signingCert, cert, claim)
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

	var cluster, subcluster string
	var deployment bool
	switch v := token.Runtime.(type) {
	case *api.GovalReplIdentity_Deployment:
		deployment = true
	case *api.GovalReplIdentity_Interactive:
		cluster = v.Interactive.Cluster
		subcluster = v.Interactive.Subcluster
	case *api.GovalReplIdentity_Hosting:
		cluster = v.Hosting.Cluster
		subcluster = v.Hosting.Subcluster
	}

	opts := verifyRawClaimsOpts{
		replid:           token.Replid,
		user:             token.User,
		cluster:          cluster,
		subcluster:       subcluster,
		deployment:       deployment,
		claims:           v.claims,
		anyReplid:        v.anyReplid,
		anyUser:          v.anyUser,
		anyCluster:       v.anyCluster,
		anySubcluster:    v.anySubcluster,
		allowsDeployment: v.deployments,
	}

	return verifyRawClaims(opts)
}

// VerifyOption specifies an additional verification step to be performed on an identity.
type VerifyOption interface {
	verify(*api.GovalReplIdentity) error
}

type funcVerifyOption struct {
	f func(identity *api.GovalReplIdentity) error
}

func (o *funcVerifyOption) verify(identity *api.GovalReplIdentity) error {
	return o.f(identity)
}

// WithVerify allows the caller to specify an arbitrary function to perform
// verification on the identity prior to it being returned.
func WithVerify(f func(identity *api.GovalReplIdentity) error) VerifyOption {
	return &funcVerifyOption{
		f: f,
	}
}

// WithSource verifies that the identity's origin replID matches the given
// source, if present. This can be used to enforce specific clients in servers
// when verifying identities.
func WithSource(sourceReplid string) VerifyOption {
	return WithVerify(func(identity *api.GovalReplIdentity) error {
		if identity.OriginReplid != "" && identity.OriginReplid != sourceReplid {
			return fmt.Errorf("identity origin replid does not match. expected %q; got %q", sourceReplid, identity.OriginReplid)
		}
		return nil
	})
}

// VerifyIdentity verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient).
//
// The optional options allow specifying additional verifications on the identity.
func VerifyIdentity(message string, audience []string, getPubKey PubKeySource, options ...VerifyOption) (*api.GovalReplIdentity, error) {
	opts := VerifyTokenOpts{
		Message:   message,
		Audience:  audience,
		GetPubKey: getPubKey,
		Options:   options,
		Flags:     []api.FlagClaim{api.FlagClaim_IDENTITY},
	}
	return VerifyToken(opts)
}

// VerifyRenewIdentity verifies that the given `REPL_RENEWAL` value is in fact
// signed by Goval's chain of authority, addressed to the provided audience
// (the `REPL_ID` of the recipient), and has the capability to renew the
// identity.
//
// The optional options allow specifying additional verifications on the identity.
func VerifyRenewIdentity(message string, audience []string, getPubKey PubKeySource, options ...VerifyOption) (*api.GovalReplIdentity, error) {
	opts := VerifyTokenOpts{
		Message:   message,
		Audience:  audience,
		GetPubKey: getPubKey,
		Options:   options,
		Flags:     []api.FlagClaim{api.FlagClaim_RENEW_IDENTITY},
	}
	return VerifyToken(opts)
}

type VerifyTokenOpts struct {
	Message   string
	Audience  []string
	GetPubKey PubKeySource
	Options   []VerifyOption
	Flags     []api.FlagClaim
}

// VerifyToken verifies that the given `REPL_IDENTITY` value is in fact
// signed by Goval's chain of authority, and addressed to the provided audience
// (the `REPL_ID` of the recipient).
//
// The optional options allow specifying additional verifications on the identity.
func VerifyToken(opts VerifyTokenOpts) (*api.GovalReplIdentity, error) {
	v, bytes, _, err := verifyChain(opts.Message, opts.GetPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed verify message: %w", err)
	}

	signingAuthority, err := getSigningAuthority(opts.Message)
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

	var validAudience bool
	for _, aud := range opts.Audience {
		if aud == identity.Aud {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, fmt.Errorf("message identity mismatch. expected %q, got %q", opts.Audience, identity.Aud)
	}

	err = v.checkClaimsAgainstToken(&identity)
	if err != nil {
		return nil, fmt.Errorf("claim mismatch: %w", err)
	}

	if v.claims != nil {
		for _, flag := range opts.Flags {
			if _, ok := v.claims.Flags[flag]; !ok {
				return nil, fmt.Errorf("token not authorized for flag %s", flag)
			}
		}
	} else if len(opts.Flags) > 0 {
		return nil, fmt.Errorf("token not authorized for flags")
	}

	for _, option := range opts.Options {
		err = option.verify(&identity)
		if err != nil {
			return nil, err
		}
	}

	return &identity, nil
}

type verifyRawClaimsOpts struct {
	replid           string
	user             string
	cluster          string
	subcluster       string
	deployment       bool
	claims           *MessageClaims
	anyReplid        bool
	anyUser          bool
	anyCluster       bool
	anySubcluster    bool
	allowsDeployment bool
}

func verifyRawClaims(
	opts verifyRawClaimsOpts,
) error {
	if opts.claims != nil {
		if opts.replid != "" && !opts.anyReplid {
			if _, ok := opts.claims.Repls[opts.replid]; !ok {
				return errors.New("not authorized (replid)")
			}
		}

		if opts.user != "" && !opts.anyUser {
			if _, ok := opts.claims.Users[opts.user]; !ok {
				return errors.New("not authorized (user)")
			}
		}

		if opts.cluster != "" && !opts.anyCluster {
			if _, ok := opts.claims.Clusters[opts.cluster]; !ok {
				return errors.New("not authorized (cluster)")
			}
		}

		if opts.subcluster != "" && !opts.anySubcluster {
			if _, ok := opts.claims.Subclusters[opts.subcluster]; !ok {
				return errors.New("not authorized (subcluster)")
			}
		}

		if opts.deployment && !opts.allowsDeployment {
			return errors.New("not authorized (deployment)")
		}
	}

	return nil
}

func verifyClaims(iat time.Time, exp time.Time, replid, user, cluster, subcluster string, deployment bool, claims *MessageClaims) error {
	if iat.After(time.Now()) {
		return fmt.Errorf("not valid for %s", time.Until(iat))
	}

	if exp.Before(time.Now()) {
		return fmt.Errorf("expired %s ago", time.Since(exp))
	}

	opts := verifyRawClaimsOpts{
		replid:     replid,
		user:       user,
		cluster:    cluster,
		subcluster: subcluster,
		deployment: deployment,
		claims:     claims,
	}

	return verifyRawClaims(opts)
}

func decodeUnsafePASETO(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("token not in PASETO format")
	}
	if parts[0] != "v2" || parts[1] != "public" {
		return nil, fmt.Errorf("token does not start with v2.public.")
	}
	bytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid token body payload: %w", err)
	}
	// v2.public tokens have a 64-byte signature after the main body.
	bytes, err = base64.StdEncoding.DecodeString(string(bytes[:len(bytes)-64]))
	if err != nil {
		return nil, fmt.Errorf("invalid token body internal payload: %w", err)
	}
	return bytes, nil
}

func decodeUnsafeReplIdentity(token string) (*api.GovalReplIdentity, error) {
	bytes, err := decodeUnsafePASETO(token)
	if err != nil {
		return nil, err
	}
	var replIdentity api.GovalReplIdentity
	err = proto.Unmarshal(bytes, &replIdentity)
	if err != nil {
		return nil, fmt.Errorf("token body not an api.GovalReplIdentity: %w", err)
	}
	return &replIdentity, nil
}

func decodeUnsafeGovalCert(token string) (*api.GovalCert, error) {
	bytes, err := decodeUnsafePASETO(token)
	if err != nil {
		return nil, err
	}
	var decodedCert api.GovalCert
	err = proto.Unmarshal(bytes, &decodedCert)
	if err != nil {
		return nil, fmt.Errorf("token body not an api.GovalReplIdentity: %w", err)
	}
	return &decodedCert, nil
}

// DebugTokenAsString returns a string representation explaining a token. It does not perform any
// validation of the token, and should be used only for debugging.
func DebugTokenAsString(token string) string {
	lines := []string{
		"raw token:",
		fmt.Sprintf("  %s", token),
	}
	marshalOptions := protojson.MarshalOptions{
		Indent:    "  ",
		Multiline: true,
	}

	// First dump the token contents.
	lines = append(lines, "decoded token:")
	replIdentity, err := decodeUnsafeReplIdentity(token)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  token decode error: %v", err))
		return strings.Join(lines, "\n")
	}
	for _, line := range strings.Split(marshalOptions.Format(replIdentity), "\n") {
		lines = append(lines, fmt.Sprintf("  %s", line))
	}
	lines = append(lines, "signing authority chain:")

	// Now dump the signing authority chain.
	for {
		signingAuthority, err := getSigningAuthority(token)
		lines = append(lines, "  signing authority:")
		if err != nil {
			lines = append(lines, fmt.Sprintf("    signing authority unmarshal error: %v", err))
			return strings.Join(lines, "\n")
		}
		for _, line := range strings.Split(marshalOptions.Format(signingAuthority), "\n") {
			lines = append(lines, fmt.Sprintf("    %s", line))
		}
		if signingAuthority.GetKeyId() != "" {
			break
		}
		lines = append(lines, "  certificate:")
		token = signingAuthority.GetSignedCert()
		cert, err := decodeUnsafeGovalCert(token)
		if err != nil {
			lines = append(lines, fmt.Sprintf("    cert unmarshal error: %v", err))
			return strings.Join(lines, "\n")
		}
		for _, line := range strings.Split(marshalOptions.Format(cert), "\n") {
			lines = append(lines, fmt.Sprintf("    %s", line))
		}
		lines = append(lines, "")
	}

	// This text is not supposed to be machine-readable, so let's make
	// it extra hard for machines to parse this by word-wrapping (also makes
	// it nice to print on a Repl).
	const wordWrapCols = 60
	var wrappedLines []string
	for _, line := range lines {
		indent := "  "
		for i := 0; i < len(line) && line[i] == ' '; i++ {
			indent += " "
		}
		for len(line) > wordWrapCols {
			wrappedLines = append(wrappedLines, line[:wordWrapCols])
			line = indent + line[wordWrapCols:]
		}
		wrappedLines = append(wrappedLines, line)
	}
	lines = wrappedLines
	return strings.Join(lines, "\n")
}
