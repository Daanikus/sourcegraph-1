package perm

import "sync"

var (
	// permissionsAllowByDefault, if set to true, grants all users access to repositories that are
	// not matched by any authz provider. The default value is true. It is only set to false in
	// error modes (when the configuration is in a state where interpreting it literally could lead
	// to leakage of private repositories).
	permissionsAllowByDefault bool = true

	authnProviders           []AuthnProvider
	authzProviders           []AuthzProvider
	identityToAuthzIDMappers []IdentityToAuthzIDMapper
	providersMu              sync.RWMutex
)

func SetProviders(permsAllowByDefault bool, n []AuthnProvider, z []AuthzProvider, m []IdentityToAuthzIDMapper) {
	providersMu.Lock()
	defer providersMu.Unlock()

	authnProviders = n
	authzProviders = z
	identityToAuthzIDMappers = m
	permissionsAllowByDefault = permsAllowByDefault
}

// DoWithAuthzProviders provides concurrency-safe access to the authz providers currently registered.
func DoWithAuthzProviders(f func(p []AuthzProvider) error) error {
	providersMu.RLock()
	defer providersMu.RUnlock()
	return f(authzProviders)
}

func AllowByDefault() bool {
	return permissionsAllowByDefault
}
