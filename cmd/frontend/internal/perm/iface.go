package perm

import (
	"context"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
)

type (
	// UserID is the user ID as supplied by a AuthnProvider.
	UserID string

	// AuthzID is the ID supplied to a AuthzProvider that is used to determine permissions.
	AuthzID string

	// P is a type of permission (e.g., "read").
	P string
)

const (
	Read P = "read"
)

// AuthnProvider supplies the current user's canonical ID. The canonical ID is that which uniquely
// identifies the user to the authentication provider ("authn provider"). The authn provider is the
// source of truth for identity that Sourcegraph shares with other related services (e.g., the code
// host). The authn provider can be any of the following:
//
// * SAML identity provider
// * OpenID Connect identity provider
// * Code host (e.g., GitHub.com, GitLab.com) if it is used to sign into other services
// * Another SSO authentication mechanism, like LDAP
//
// The authn provider should also be the sign-in mechanism for Sourcegraph.
//
// In most cases, an AuthnProvider implementation will just return the current user's Sourcegraph
// username (which will be the same username as provided by the authn provider).
type AuthnProvider interface {
	CurrentIdentity(ctx context.Context) (id UserID, isAdmin bool, err error)
}

// AuthzProvider defines a source of truth of which repositories a user is authorized to view. The
// user is identified by a AuthzID. In most cases, the AuthzID is equivalent to the UserID supplied
// by the AuthnProvider, but in some cases, the authz provider has its own internal definition of
// identity which must be mapped from the authn provider identity. The IdentityToAuthzID interface
// handles this mapping. Examples of authz providers include the following:
//
// * Code host
// * LDAP groups
// * SAML identity provider (via SAML group permissions)
//
// In most cases, the code host is the authz provider, because it is the source of truth for
// repository permissions.
//
// In most cases, an AuthzID will be a username in the authz provider, but this is not strictly
// necessary.  For instance, an AuthzID could be the name of a role that is sufficient for the authz
// provider to determine permissions.
type AuthzProvider interface {
	// Repos partitions the set of repositories into two sets: the set of repositories for which
	// this AuthzProvider is the source of permissions and the set of repositories for which it is
	// not. Each repository in the input set must be represented in exactly one of the output sets.
	Repos(ctx context.Context, repos map[Repo]struct{}) (mine map[Repo]struct{}, others map[Repo]struct{})

	// RepoPerms returns a map where the keys comprise a subset of the input repos to which the user
	// identified by authzID has access. The values of the map indicate which permissions the user
	// has for each repo. Every repo in the input set is represented in the output map if the repo
	// permissions derive from this AuthzProvider. If a repo does not exist in the output
	// permissions map, that means the repo's permissions are not handled by this AuthzProvider.
	//
	// Design note: this is a better interface than ListAllRepos, because in some cases, the list of
	// all repos may be very long (especially if the returned list includes public repos). RepoPerms
	// is a sufficient interface for all current use cases and leaves up to the implementation which
	// repo permissions it needs to compute.  In practice, most will probably use a combination of
	// (1) "list all private repos the user has access to", (2) a mechanism to determine which repos
	// are public/private, and (3) a cache of some sort.
	RepoPerms(ctx context.Context, userAccount *extsvc.ExternalAccount, repos map[Repo]struct{}) (map[api.RepoURI]map[P]bool, error)

	GetAccount(ctx context.Context, user *types.User, current []*extsvc.ExternalAccount) (mine *extsvc.ExternalAccount, isNew bool)
}

// IdentityToAuthzIDMapper maps UserIDs (from a AuthnProvider) to AuthzIDs (to a AuthzProvider).
//
// In most cases, the UserID is string-equivalent to the AuthzID (in such cases, use the
// IdentityMapper implementation of this intefacE). However, this is not guaranteed. For instance,
// some code hosts may have a different internal username than the username supplied by the SSO
// login service.
//
// It is recommended to keep implementations of this interface as simple and cheap as
// possible. Clients of this interface will invoke the AuthzID method as if it is a cheap operation
// that doesn't involve network calls, etc. E.g., don't return an access token for the authzID,
// because it's good to give that responsibility to the AuthzProvider in case API rate limits are a
// concern.
type IdentityToAuthzIDMapper interface {
	// AuthzID returns the authzID to use for the given AuthzProvider. This will
	// be the identity function in most cases. Returns the empty string if no authz identity
	// matches.
	AuthzID(u UserID, a AuthzProvider) AuthzID
}

type Repo struct {
	// URI is the unique name/path of the repo on Sourcegraph
	URI api.RepoURI

	// ExternalRepoSpec uniquely identifies the external repo that is the source of the repo.
	api.ExternalRepoSpec
}
