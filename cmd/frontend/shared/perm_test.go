package shared

import (
	"context"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/schema"
)

type newGitLabAuthzProviderParams struct {
	baseURL         string
	sudoToken       string
	repoPathPattern string
	matchPattern    string
	ttl             time.Duration
}

func (m newGitLabAuthzProviderParams) RepoPerms(ctx context.Context, authzID perm.AuthzID, repos map[perm.Repo]struct{}) (map[api.RepoURI]map[perm.P]bool, error) {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) Repos(ctx context.Context, repos map[perm.Repo]struct{}) (mine map[perm.Repo]struct{}, others map[perm.Repo]struct{}) {
	panic("should never be called")
}

func Test_providersFromConfig(t *testing.T) {
	mockNewGitLabAuthzProvider = func(baseURL *url.URL, sudoToken, repoPathPattern, matchPattern string, ttl time.Duration, cache interface{}) perm.AuthzProvider {
		return newGitLabAuthzProviderParams{
			baseURL:         baseURL.String(),
			sudoToken:       sudoToken,
			repoPathPattern: repoPathPattern,
			matchPattern:    matchPattern,
			ttl:             ttl,
		}
	}

	tests := []struct {
		cfg                          schema.SiteConfiguration
		expPermissionsAllowByDefault bool
		expAuthnProviders            []perm.AuthnProvider
		expAuthzProviders            []perm.AuthzProvider
		expIdentityMappers           []perm.IdentityToAuthzIDMapper
		expSeriousProblems           []string
		expWarnings                  []string
	}{
		{
			cfg: schema.SiteConfiguration{
				Gitlab: []*schema.GitLabConnection{{
					PermissionsIgnore:  false,
					PermissionsMatcher: "gitlab.mine/*",
					PermissionsTtl:     "48h",
					Url:                "https://gitlab.mine",
					Token:              "asdf",
				}},
			},
			expPermissionsAllowByDefault: true,
			expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
			expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
			expAuthzProviders: []perm.AuthzProvider{
				newGitLabAuthzProviderParams{
					baseURL:         "https://gitlab.mine",
					sudoToken:       "asdf",
					repoPathPattern: "",
					matchPattern:    "gitlab.mine/*",
					ttl:             48 * time.Hour,
				},
			},
			expSeriousProblems: nil,
			expWarnings:        nil,
		},
		{
			cfg: schema.SiteConfiguration{
				Gitlab: []*schema.GitLabConnection{{
					PermissionsIgnore:     false,
					PermissionsMatcher:    "asdf/gitlab.mine/*",
					PermissionsTtl:        "48h",
					RepositoryPathPattern: "asdf/{host}/{pathWithNamespace}",
					Url:                   "https://gitlab.mine",
					Token:                 "asdf",
				}},
			},
			expPermissionsAllowByDefault: true,
			expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
			expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
			expAuthzProviders: []perm.AuthzProvider{
				newGitLabAuthzProviderParams{
					baseURL:         "https://gitlab.mine",
					sudoToken:       "asdf",
					repoPathPattern: "asdf/{host}/{pathWithNamespace}",
					matchPattern:    "asdf/gitlab.mine/*",
					ttl:             48 * time.Hour,
				},
			},
			expSeriousProblems: nil,
			expWarnings:        nil,
		},
		{
			cfg: schema.SiteConfiguration{
				Gitlab: []*schema.GitLabConnection{{
					PermissionsIgnore:  false,
					PermissionsMatcher: "",
					Url:                "https://gitlab.mine",
					Token:              "asdf",
				}},
			},
			expPermissionsAllowByDefault: false,
			expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
			expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
			expAuthzProviders: []perm.AuthzProvider{
				newGitLabAuthzProviderParams{
					baseURL:   "https://gitlab.mine",
					sudoToken: "asdf",
					ttl:       24 * time.Hour,
				},
			},
			expSeriousProblems: []string{
				"GitLab connection \"https://gitlab.mine\" should specify a `permissions.matcher` string starting with \"*/\" or ending with \"/*\".",
			},
			expWarnings: []string{
				`Could not parse time duration "", falling back to 24 hours.`,
			},
		},
		{
			cfg: schema.SiteConfiguration{
				Gitlab: []*schema.GitLabConnection{{
					PermissionsIgnore: false,
					Url:               "http://not a url",
				}},
			},
			expPermissionsAllowByDefault: false,
			expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
			expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
			expAuthzProviders:            nil,
			expSeriousProblems: []string{
				`Could not parse URL for GitLab instance "http://not a url": parse http://not a url: invalid character " " in host name`,
			},
			expWarnings: nil,
		},
		{
			cfg: schema.SiteConfiguration{
				Gitlab: []*schema.GitLabConnection{{
					PermissionsIgnore: true,
					Url:               "https://gitlab.mine",
				}},
			},
			expPermissionsAllowByDefault: true,
			expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
			expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
			expAuthzProviders:            nil,
			expSeriousProblems:           nil,
			expWarnings:                  nil,
		},
	}

	for _, test := range tests {
		permissionsAllowByDefault, authnProviders, authzProviders, identityMappers, seriousProblems, warnings := providersFromConfig(&test.cfg)
		if permissionsAllowByDefault != test.expPermissionsAllowByDefault {
			t.Errorf("permissionsAllowByDefault: %v != %v", permissionsAllowByDefault, test.expPermissionsAllowByDefault)
		}
		if !reflect.DeepEqual(authnProviders, test.expAuthnProviders) {
			t.Errorf("authnProviders: %+v != %+v", authnProviders, test.expAuthnProviders)
		}
		if !reflect.DeepEqual(authzProviders, test.expAuthzProviders) {
			t.Errorf("authzProviders: %+v != %+v", authzProviders, test.expAuthzProviders)
		}
		if !reflect.DeepEqual(identityMappers, test.expIdentityMappers) {
			t.Errorf("identityMappers: %+v != %+v", identityMappers, test.expIdentityMappers)
		}
		if !reflect.DeepEqual(seriousProblems, test.expSeriousProblems) {
			t.Errorf("seriousProblems: %+v != %+v", seriousProblems, test.expSeriousProblems)
		}
		if !reflect.DeepEqual(warnings, test.expWarnings) {
			t.Errorf("warnings: %+v != %+v", warnings, test.expWarnings)
		}
	}
}
