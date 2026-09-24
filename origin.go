package replidentity

import (
	"fmt"

	"github.com/replit/go-replidentity/protos/external/goval/api"
)

// OriginVerificationResult describes an origin check on an already verified token.
type OriginVerificationResult string

const (
	OriginVerified          OriginVerificationResult = "verified"
	OriginMissingClaim      OriginVerificationResult = "missing_claim"
	OriginMismatch          OriginVerificationResult = "mismatch"
	OriginBuildInfoMismatch OriginVerificationResult = "build_info_mismatch"
)

// VerifyOrigin checks only the leaf certificate's origin authority, including an
// explicit empty origin claim. Ancestor wildcards do not grant leaf authority.
func (token *VerifiedToken) VerifyOrigin() OriginVerificationResult {
	identity := token.Identity
	if token.Certificate != nil {
		found, authorized := false, false
		for _, claim := range token.Certificate.Claims {
			switch value := claim.Claim.(type) {
			case *api.CertificateClaim_OriginReplid:
				found = true
				authorized = authorized || value.OriginReplid == identity.OriginReplid
			case *api.CertificateClaim_Flag:
				if value.Flag == api.FlagClaim_ANY_ORIGIN_REPLID {
					found, authorized = true, true
				}
			}
		}
		if !found {
			return OriginMissingClaim
		}
		if !authorized {
			return OriginMismatch
		}
	}
	if origin := identity.GetBuildInfo().GetOriginReplId(); origin != "" && origin != identity.OriginReplid {
		return OriginBuildInfoMismatch
	}
	return OriginVerified
}

type originVerifyOption struct {
	enforce bool
	observe func(OriginVerificationResult)
}

func (option originVerifyOption) verify(token *VerifiedToken) error {
	result := token.VerifyOrigin()
	if option.observe != nil {
		option.observe(result)
	}
	if option.enforce && result != OriginVerified {
		return fmt.Errorf("not authorized (originReplid): %s", result)
	}
	return nil
}

// WithOriginVerification reports the origin check to observe when provided.
// Set enforce only after issuers and existing credentials carry origin claims.
func WithOriginVerification(enforce bool, observe func(OriginVerificationResult)) VerifyOption {
	return originVerifyOption{enforce: enforce, observe: observe}
}
