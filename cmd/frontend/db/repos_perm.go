package db

import (
	"context"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/actor"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
)

var mockAuthzFilter func(ctx context.Context, repos []*types.Repo, p perm.P) ([]*types.Repo, error)

// authzFilter is the enforcement mechanism for repository permissions. It accepts a list of repositories
// and a permission type `p` and returns a subset of those repositories (no guarantee on order) for
// which the currently authenticated user has the specified permission.
func authzFilter(ctx context.Context, repos []*types.Repo, p perm.P) ([]*types.Repo, error) {
	if mockAuthzFilter != nil {
		return mockAuthzFilter(ctx, repos, p)
	}

	if len(repos) == 0 {
		return repos, nil
	}
	if isInternalActor(ctx) {
		return repos, nil
	}

	filteredURIs, acceptAll, err := getFilteredRepoURIs(ctx, perm.ToRepos(repos), p)
	if err != nil {
		return nil, err
	}
	if acceptAll {
		return repos, nil
	}

	filteredRepos := make([]*types.Repo, 0, len(filteredURIs))
	for _, repo := range repos {
		if _, ok := filteredURIs[repo.URI]; ok {
			filteredRepos = append(filteredRepos, repo)
		}
	}
	return filteredRepos, nil
}

// isInternalActor returns true if the actor represents an internal agent (i.e., non-user-bound
// request that originates from within Sourcegraph itself).
//
// 🚨 SECURITY: internal requests bypass authz provider permissions checks, so correctness is
// important here.
func isInternalActor(ctx context.Context) bool {
	return actor.FromContext(ctx).Internal
}

func getFilteredRepoURIs(ctx context.Context, repos map[perm.Repo]struct{}, p perm.P) (
	accepted map[api.RepoURI]struct{}, acceptAll bool, err error,
) {
	var (
		currentUser *types.User
		accts       []*extsvc.ExternalAccount
	)
	if perm.NumAuthzProviders() > 0 && actor.FromContext(ctx).IsAuthenticated() {
		var err error
		currentUser, err = Users.GetByCurrentAuthUser(ctx)
		if err != nil {
			return nil, false, err
		}
		accts, err = ExternalAccounts.List(ctx, ExternalAccountsListOptions{
			UserID: currentUser.ID,
		})
		if err != nil {
			return nil, false, err
		}
	}

	accepted = make(map[api.RepoURI]struct{})
	unverified := make(map[perm.Repo]struct{})
	for repo := range repos {
		unverified[repo] = struct{}{}
	}

	// Walk through all authz providers, checking repo permissions against each. If any own a given
	// repo, we use its permissions for that repo.
	if err := perm.DoWithAuthzProviders(func(authzProviders []perm.AuthzProvider) error {
		for _, authzProvider := range authzProviders {
			if len(unverified) == 0 {
				break
			}
			acct, isNew, err := authzProvider.GetAccount(ctx, currentUser, accts)
			if err != nil {
				return err
			}
			if currentUser != nil && isNew { // If new account, save it so we remember it later.
				err := ExternalAccounts.AssociateUserAndSave(ctx, currentUser.ID, acct.ExternalAccountSpec, acct.ExternalAccountData)
				if err != nil {
					return err
				}
			}
			perms, err := authzProvider.RepoPerms(ctx, acct, unverified)
			if err != nil {
				return err
			}

			newUnverified := make(map[perm.Repo]struct{})
			for unverifiedRepo := range unverified {
				repoPerms, ok := perms[unverifiedRepo.URI]
				if !ok {
					newUnverified[unverifiedRepo] = struct{}{}
					continue
				}
				if repoPerms[p] {
					accepted[unverifiedRepo.URI] = struct{}{}
				}
			}
			unverified = newUnverified
		}
		return nil
	}); err != nil {
		return nil, false, err
	}

	if perm.AllowByDefault() {
		for r := range unverified {
			accepted[r.URI] = struct{}{}
		}
	}

	return accepted, false, nil
}
