package perm

import "github.com/sourcegraph/sourcegraph/cmd/frontend/types"

// IdentityMapper maps the user ID to the authz ID that is string-equivalent. This assumes that the
// ID used by the authn provider is equal to the ID used by the authz provider, which typically
// holds if Sourcegraph and the code host (authz provider) share the same authentication mechanism
// (typically some form of SSO). It does not hold if the authentication mechanism is different
// (e.g., when using Sourcegraph native auth).
type IdentityMapper struct{}

var _ IdentityToAuthzIDMapper = IdentityMapper{}

func (m IdentityMapper) AuthzID(u UserID, a AuthzProvider) AuthzID {
	return AuthzID(u)
}

func ToRepos(src []*types.Repo) (dst map[Repo]struct{}) {
	dst = make(map[Repo]struct{})
	for _, r := range src {
		rp := Repo{URI: r.URI}
		if r.ExternalRepo != nil {
			rp.ExternalRepoSpec = *r.ExternalRepo
		}
		dst[rp] = struct{}{}
	}
	return dst
}
