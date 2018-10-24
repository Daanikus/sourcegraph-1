package perm

import (
	"context"
	"reflect"
	"testing"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
)

func TestFilter(t *testing.T) {
	type queryTestCase struct {
		description      string
		mockID           MockIDContextItem
		repos            []*types.Repo
		expFilteredRepos []*types.Repo
		perm             P
	}
	tests := []struct {
		description         string
		permsAllowByDefault bool
		authzProviders      []AuthzProvider
		identityMappers     []IdentityToAuthzIDMapper
		queries             []queryTestCase
	}{{
		description:         "1 authz provider, 1 authn provider, 1 id mapper",
		permsAllowByDefault: true,
		identityMappers:     []IdentityToAuthzIDMapper{IdentityMapper{}},
		authzProviders: []AuthzProvider{
			&MockAuthzProvider{
				repos: map[api.RepoURI]struct{}{
					"gitlab.mine/u0/r0":     struct{}{},
					"gitlab.mine/u1/r0":     struct{}{},
					"gitlab.mine/public/r0": struct{}{},
				},
				perms: map[AuthzID]map[api.RepoURI]map[P]bool{
					"u0": map[api.RepoURI]map[P]bool{
						"gitlab.mine/u0/r0":     map[P]bool{Read: true},
						"gitlab.mine/u1/r0":     map[P]bool{},
						"gitlab.mine/public/r0": map[P]bool{Read: true},
					},
					"u1": map[api.RepoURI]map[P]bool{
						"gitlab.mine/u0/r0":     map[P]bool{},
						"gitlab.mine/u1/r0":     map[P]bool{Read: true},
						"gitlab.mine/public/r0": map[P]bool{Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description: "u0 can read its own repo",
				mockID:      MockIDContextItem{id: "u0"},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
				},
				perm: Read,
			}, {
				description: "u0 not allowed to read u1's repo",
				mockID:      MockIDContextItem{id: "u0"},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				perm: Read,
			}, {
				description: "u1 not allowed to read u0's repo",
				mockID:      MockIDContextItem{id: "u1"},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				perm: Read,
			}, {
				description: "u99 not allowed to read anyone's repo",
				mockID:      MockIDContextItem{id: "u99"},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{},
				perm:             Read,
			}, {
				description: "u99 can read unmanaged repo",
				mockID:      MockIDContextItem{id: "u99"},
				repos: []*types.Repo{
					{URI: "other.mine/r"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "other.mine/r"},
				},
				perm: Read,
			}, {
				description: "u0 can read its own, public, and unmanaged repos",
				mockID:      MockIDContextItem{id: "u0"},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u0/r0"},
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				perm: Read,
			},
		},
	}, {
		description:         "2 authz providers, 1 authn provider, 1 id mapper",
		permsAllowByDefault: true,
		identityMappers:     []IdentityToAuthzIDMapper{IdentityMapper{}},
		authzProviders: []AuthzProvider{
			&MockAuthzProvider{
				repos: map[api.RepoURI]struct{}{
					"gitlab0.mine/u0/r0":     struct{}{},
					"gitlab0.mine/u1/r0":     struct{}{},
					"gitlab0.mine/public/r0": struct{}{},
				},
				perms: map[AuthzID]map[api.RepoURI]map[P]bool{
					"u0": map[api.RepoURI]map[P]bool{
						"gitlab0.mine/u0/r0":     map[P]bool{Read: true},
						"gitlab0.mine/u1/r0":     map[P]bool{},
						"gitlab0.mine/public/r0": map[P]bool{Read: true},
					},
					"u1": map[api.RepoURI]map[P]bool{
						"gitlab0.mine/u0/r0":     map[P]bool{},
						"gitlab0.mine/u1/r0":     map[P]bool{Read: true},
						"gitlab0.mine/public/r0": map[P]bool{Read: true},
					},
				},
			},
			&MockAuthzProvider{
				repos: map[api.RepoURI]struct{}{
					"gitlab1.mine/u0/r0":     struct{}{},
					"gitlab1.mine/u1/r0":     struct{}{},
					"gitlab1.mine/public/r0": struct{}{},
				},
				perms: map[AuthzID]map[api.RepoURI]map[P]bool{
					"u0": map[api.RepoURI]map[P]bool{
						"gitlab1.mine/u0/r0":     map[P]bool{Read: true},
						"gitlab1.mine/u1/r0":     map[P]bool{},
						"gitlab1.mine/public/r0": map[P]bool{Read: true},
					},
					"u1": map[api.RepoURI]map[P]bool{
						"gitlab1.mine/u0/r0":     map[P]bool{},
						"gitlab1.mine/u1/r0":     map[P]bool{Read: true},
						"gitlab1.mine/public/r0": map[P]bool{Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description: "u0 can read its own repos, but not others'",
				mockID:      MockIDContextItem{id: "u0"},
				repos: []*types.Repo{
					{URI: "gitlab0.mine/u0/r0"},
					{URI: "gitlab0.mine/u1/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u0/r0"},
					{URI: "gitlab1.mine/u1/r0"},
					{URI: "gitlab1.mine/public/r0"},
					{URI: "gitlab2.mine/u1/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab0.mine/u0/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u0/r0"},
					{URI: "gitlab1.mine/public/r0"},
					{URI: "gitlab2.mine/u1/r0"},
					{URI: "otherHost/r0"},
				},
				perm: Read,
			},
		},
	}, {
		description:         "2 authz providers, 1 authn provider, 1 id mapper, permsAllowByDefault=false",
		permsAllowByDefault: false,
		identityMappers:     []IdentityToAuthzIDMapper{IdentityMapper{}},
		authzProviders: []AuthzProvider{
			&MockAuthzProvider{
				repos: map[api.RepoURI]struct{}{
					"gitlab0.mine/u0/r0":     struct{}{},
					"gitlab0.mine/u1/r0":     struct{}{},
					"gitlab0.mine/public/r0": struct{}{},
				},
				perms: map[AuthzID]map[api.RepoURI]map[P]bool{
					"u0": map[api.RepoURI]map[P]bool{
						"gitlab0.mine/u0/r0":     map[P]bool{Read: true},
						"gitlab0.mine/u1/r0":     map[P]bool{},
						"gitlab0.mine/public/r0": map[P]bool{Read: true},
					},
					"u1": map[api.RepoURI]map[P]bool{
						"gitlab0.mine/u0/r0":     map[P]bool{},
						"gitlab0.mine/u1/r0":     map[P]bool{Read: true},
						"gitlab0.mine/public/r0": map[P]bool{Read: true},
					},
				},
			},
			&MockAuthzProvider{
				repos: map[api.RepoURI]struct{}{
					"gitlab1.mine/u0/r0":     struct{}{},
					"gitlab1.mine/u1/r0":     struct{}{},
					"gitlab1.mine/public/r0": struct{}{},
				},
				perms: map[AuthzID]map[api.RepoURI]map[P]bool{
					"u0": map[api.RepoURI]map[P]bool{
						"gitlab1.mine/u0/r0":     map[P]bool{Read: true},
						"gitlab1.mine/u1/r0":     map[P]bool{},
						"gitlab1.mine/public/r0": map[P]bool{Read: true},
					},
					"u1": map[api.RepoURI]map[P]bool{
						"gitlab1.mine/u0/r0":     map[P]bool{},
						"gitlab1.mine/u1/r0":     map[P]bool{Read: true},
						"gitlab1.mine/public/r0": map[P]bool{Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description: "u0 can read its own repos, but not others'",
				mockID:      MockIDContextItem{id: "u0"},
				repos: []*types.Repo{
					{URI: "gitlab0.mine/u0/r0"},
					{URI: "gitlab0.mine/u1/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u0/r0"},
					{URI: "gitlab1.mine/u1/r0"},
					{URI: "gitlab1.mine/public/r0"},
					{URI: "gitlab2.mine/u1/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab0.mine/u0/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u0/r0"},
					{URI: "gitlab1.mine/public/r0"},
				},
				perm: Read,
			},
		},
	}}

	for _, test := range tests {
		t.Logf("Running test %q", test.description)
		SetProviders(test.permsAllowByDefault, []AuthnProvider{MockAuthnProvider{}}, test.authzProviders, test.identityMappers)
		for _, q := range test.queries {
			t.Logf("Running query %q", q.description)
			ctx := context.WithValue(context.Background(), mockIDKey, q.mockID)
			filteredRepos, err := Filter(ctx, q.repos, q.perm)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(filteredRepos, q.expFilteredRepos) {
				r := make([]api.RepoURI, len(q.repos))
				for i, v := range q.repos {
					r[i] = v.URI
				}
				a := make([]api.RepoURI, len(filteredRepos))
				for i, v := range filteredRepos {
					a[i] = v.URI
				}
				e := make([]api.RepoURI, len(q.expFilteredRepos))
				for i, v := range q.expFilteredRepos {
					e[i] = v.URI
				}
				t.Errorf("For id %v and input repos %v,\nexpected filtered repos\n\t%v\n, but got\n\t%v", q.mockID, r, e, a)
			}
		}
	}
}

const mockIDKey = "mockIDKey"

type MockIDContextItem struct {
	id      UserID
	isAdmin bool
	err     error
}

type MockAuthnProvider struct{}

func (m MockAuthnProvider) CurrentIdentity(ctx context.Context) (id UserID, isAdmin bool, err error) {
	v := ctx.Value(mockIDKey).(MockIDContextItem)
	return v.id, v.isAdmin, v.err
}

type MockAuthzProvider struct {
	perms map[AuthzID]map[api.RepoURI]map[P]bool
	repos map[api.RepoURI]struct{}
}

func (m *MockAuthzProvider) RepoPerms(ctx context.Context, authzID AuthzID, repos map[Repo]struct{}) (map[api.RepoURI]map[P]bool, error) {
	retPerms := make(map[api.RepoURI]map[P]bool)
	repos, _ = m.Repos(ctx, repos)

	var userPerms map[api.RepoURI]map[P]bool = m.perms[authzID]
	for repo := range repos {
		retPerms[repo.URI] = make(map[P]bool)
		for k, v := range userPerms[repo.URI] {
			retPerms[repo.URI][k] = v
		}
	}
	return retPerms, nil
}

func (m *MockAuthzProvider) Repos(ctx context.Context, repos map[Repo]struct{}) (mine map[Repo]struct{}, others map[Repo]struct{}) {
	mine, others = make(map[Repo]struct{}), make(map[Repo]struct{})
	for repo := range repos {
		if _, ok := m.repos[repo.URI]; ok {
			mine[repo] = struct{}{}
		} else {
			others[repo] = struct{}{}
		}
	}
	return mine, others
}
