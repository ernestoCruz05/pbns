package time

import (
	"errors"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/enrollment"
	"pbns.local/gateway/internal/store"
)

type StoreHostResolver struct {
	Store *store.Store
}

func (resolver StoreHostResolver) ResolveHost(fingerprint [32]byte) (cose.Verifier, error) {
	if resolver.Store == nil {
		return nil, ErrHostAuthentication
	}
	host, err := resolver.Store.GetHost(fingerprint)
	if err != nil {
		return nil, errors.Join(ErrHostAuthentication, err)
	}
	verifier, resolvedFingerprint, err := enrollment.IdentityVerifier(host.IdentityCOSEKey)
	if err != nil || resolvedFingerprint != fingerprint {
		return nil, ErrHostAuthentication
	}
	return verifier, nil
}
