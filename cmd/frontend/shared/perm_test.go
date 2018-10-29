package shared

import (
	"context"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm/gitlab"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/schema"
)

type newGitLabAuthzProviderParams struct {
	Op gitlab.GitLabAuthzProviderOp
}

func (m newGitLabAuthzProviderParams) RepoPerms(ctx context.Context, account *extsvc.ExternalAccount, repos map[perm.Repo]struct{}) (map[api.RepoURI]map[perm.P]bool, error) {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) Repos(ctx context.Context, repos map[perm.Repo]struct{}) (mine map[perm.Repo]struct{}, others map[perm.Repo]struct{}) {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) GetAccount(ctx context.Context, user *types.User, current []*extsvc.ExternalAccount) (mine *extsvc.ExternalAccount, isNew bool, err error) {
	panic("should never be called")
}

func Test_providersFromConfig(t *testing.T) {
	NewGitLabAuthzProvider = func(op gitlab.GitLabAuthzProviderOp) perm.AuthzProvider {
		op.MockCache = nil // ignore cache value
		return newGitLabAuthzProviderParams{op}
	}

	tests := []struct {
		description                  string
		cfg                          schema.SiteConfiguration
		expPermissionsAllowByDefault bool
		expAuthzProviders            []perm.AuthzProvider
		expSeriousProblems           []string
		expWarnings                  []string
	}{
		{
			cfg: schema.SiteConfiguration{
				Gitlab: []*schema.GitLabConnection{{
					PermissionsIgnore:  false,
					PermissionsMatcher: "gitlab.mine/*",
					PermissionsTtl:     "48h",
					PermissionsAuthnProvider: &schema.PermissionsAuthnProvider{
						ServiceID:      "https://okta.mine/",
						Type:           "saml",
						GitlabProvider: "okta",
					},
					Url:   "https://gitlab.mine",
					Token: "asdf",
				}},
			},
			expPermissionsAllowByDefault: true,
			expAuthzProviders: []perm.AuthzProvider{
				newGitLabAuthzProviderParams{
					Op: gitlab.GitLabAuthzProviderOp{
						BaseURL:                  mustURLParse(t, "https://gitlab.mine"),
						IdentityServiceID:        "https://okta.mine/",
						IdentityServiceType:      "saml",
						GitLabIdentityProviderID: "okta",
						MatchPattern:             "gitlab.mine/*",
						SudoToken:                "asdf",
						CacheTTL:                 48 * time.Hour,
					},
				},
			},
			expSeriousProblems: nil,
			expWarnings:        nil,
		},
		// {
		// 	cfg: schema.SiteConfiguration{
		// 		Gitlab: []*schema.GitLabConnection{{
		// 			PermissionsIgnore:     false,
		// 			PermissionsMatcher:    "asdf/gitlab.mine/*",
		// 			PermissionsTtl:        "48h",
		// 			RepositoryPathPattern: "asdf/{host}/{pathWithNamespace}",
		// 			Url:                   "https://gitlab.mine",
		// 			Token:                 "asdf",
		// 		}},
		// 	},
		// 	expPermissionsAllowByDefault: true,
		// 	expAuthzProviders: []perm.AuthzProvider{
		// 		newGitLabAuthzProviderParams{
		// 			Op: gitlab.GitLabAuthzProviderOp{
		// 				BaseURL:                  mustURLParse(t, "https://gitlab.mine"),
		// 				IdentityServiceID:        "https://okta.mine/",
		// 				IdentityServiceType:      "saml",
		// 				GitLabIdentityProviderID: "okta",
		// 				MatchPattern:             "gitlab.mine/*",
		// 				SudoToken:                "asdf",
		// 				CacheTTL:                 48 * time.Hour,
		// 			},
		// 		},
		// 	},
		// 	expSeriousProblems: nil,
		// 	expWarnings:        nil,
		// },
		// {
		// 	cfg: schema.SiteConfiguration{
		// 		Gitlab: []*schema.GitLabConnection{{
		// 			PermissionsIgnore:  false,
		// 			PermissionsMatcher: "",
		// 			Url:                "https://gitlab.mine",
		// 			Token:              "asdf",
		// 		}},
		// 	},
		// 	expPermissionsAllowByDefault: false,
		// 	expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
		// 	expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
		// 	expAuthzProviders: []perm.AuthzProvider{
		// 		newGitLabAuthzProviderParams{
		// 			baseURL:   "https://gitlab.mine",
		// 			sudoToken: "asdf",
		// 			ttl:       24 * time.Hour,
		// 		},
		// 	},
		// 	expSeriousProblems: []string{
		// 		"GitLab connection \"https://gitlab.mine\" should specify a `permissions.matcher` string starting with \"*/\" or ending with \"/*\".",
		// 	},
		// 	expWarnings: []string{
		// 		`Could not parse time duration "", falling back to 24 hours.`,
		// 	},
		// },
		// {
		// 	cfg: schema.SiteConfiguration{
		// 		Gitlab: []*schema.GitLabConnection{{
		// 			PermissionsIgnore: false,
		// 			Url:               "http://not a url",
		// 		}},
		// 	},
		// 	expPermissionsAllowByDefault: false,
		// 	expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
		// 	expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
		// 	expAuthzProviders:            nil,
		// 	expSeriousProblems: []string{
		// 		`Could not parse URL for GitLab instance "http://not a url": parse http://not a url: invalid character " " in host name`,
		// 	},
		// 	expWarnings: nil,
		// },
		// {
		// 	cfg: schema.SiteConfiguration{
		// 		Gitlab: []*schema.GitLabConnection{{
		// 			PermissionsIgnore: true,
		// 			Url:               "https://gitlab.mine",
		// 		}},
		// 	},
		// 	expPermissionsAllowByDefault: true,
		// 	expAuthnProviders:            []perm.AuthnProvider{StandardAuthnProvider{}},
		// 	expIdentityMappers:           []perm.IdentityToAuthzIDMapper{perm.IdentityMapper{}},
		// 	expAuthzProviders:            nil,
		// 	expSeriousProblems:           nil,
		// 	expWarnings:                  nil,
		// },
	}

	for _, test := range tests {
		permissionsAllowByDefault, authzProviders, seriousProblems, warnings := providersFromConfig(&test.cfg)
		if permissionsAllowByDefault != test.expPermissionsAllowByDefault {
			t.Errorf("permissionsAllowByDefault: %v != %v", permissionsAllowByDefault, test.expPermissionsAllowByDefault)
		}
		if !reflect.DeepEqual(authzProviders, test.expAuthzProviders) {
			t.Errorf("authzProviders: %+v != %+v", authzProviders, test.expAuthzProviders)
		}
		if !reflect.DeepEqual(seriousProblems, test.expSeriousProblems) {
			t.Errorf("seriousProblems: %+v != %+v", seriousProblems, test.expSeriousProblems)
		}
		if !reflect.DeepEqual(warnings, test.expWarnings) {
			t.Errorf("warnings: %+v != %+v", warnings, test.expWarnings)
		}
	}
}

func mustURLParse(t *testing.T, u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
