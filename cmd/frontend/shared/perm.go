package shared

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/db"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	permgl "github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm/gitlab"
	"github.com/sourcegraph/sourcegraph/pkg/conf"
	"github.com/sourcegraph/sourcegraph/schema"
	log15 "gopkg.in/inconshreveable/log15.v2"
)

func init() {
	conf.ContributeValidator(func(cfg schema.SiteConfiguration) []string {
		_, _, _, _, seriousProblems, warnings := providersFromConfig(&cfg)
		return append(seriousProblems, warnings...)
	})
	conf.Watch(func() {
		permissionsAllowByDefault, authnProviders, authzProviders, identityMappers, _, _ := providersFromConfig(conf.Get())
		perm.SetProviders(permissionsAllowByDefault, authnProviders, authzProviders, identityMappers)
	})
}

type StandardAuthnProvider struct{}

func (m StandardAuthnProvider) CurrentIdentity(ctx context.Context) (perm.UserID, bool, error) {
	usr, err := db.Users.GetByCurrentAuthUser(ctx)
	if err != nil {
		return "", false, err
	}
	return perm.UserID(usr.Username), usr.SiteAdmin, nil
}

// providersFromConfig returns the set of permission-related providers derived from the site config.
// It also returns any validation problems with the config, separating these into "serious problems"
// and "warnings".  "Serious problems" are those that should make Sourcegraph set
// perm.permissionsAllowByDefault to false. "Warnings" are all other validation problems.
func providersFromConfig(cfg *schema.SiteConfiguration) (
	permissionsAllowByDefault bool,
	authnProviders []perm.AuthnProvider,
	authzProviders []perm.AuthzProvider,
	identityMappers []perm.IdentityToAuthzIDMapper,
	seriousProblems []string,
	warnings []string,
) {
	permissionsAllowByDefault = true
	defer func() {
		if len(seriousProblems) > 0 {
			log15.Error("Repository permission config was invalid (errors are visible in the UI as an admin user, you should fix ASAP). Restricting access to repositories by default for now to be safe.")
			permissionsAllowByDefault = false
		}
	}()

	// Warn if native auth is enabled and any code host permissions are enabled.
	if !configHasOnlyExternalAuth(cfg) {
		for _, gl := range cfg.Gitlab {
			if !gl.PermissionsIgnore {
				warnings = append(warnings, fmt.Sprintf("Native authentication is enabled and a GitLabConnection %q does not have `permissions.ignore` set to true. Sourcegraph assumes its username is the same as the username on the code host when enforcing permissions. With native authentication, Sourcegraph usernames may not be the same as the code host username, which is a security issue. Please consider configuring Sourcegraph to use the same sign-in mechanism that is used for the code host, or set `permissions.ignore` to true to explicitly ignore GitLab repository permissions.", gl.Url))
			}
		}
	}

	// Authentication provider
	authnProviders = append(authnProviders, StandardAuthnProvider{})

	// Authentication ID to authorization provider ID mapper. Currently, we always use the
	// IdentityMapper, which assumes the Sourcegraph username is the same as the code host
	// username.
	identityMappers = append(identityMappers, perm.IdentityMapper{})

	// Authorization (i.e., permissions) providers
	for _, gl := range cfg.Gitlab {
		if gl.PermissionsIgnore {
			continue
		}

		glURL, err := url.Parse(gl.Url)
		if err != nil {
			seriousProblems = append(seriousProblems, fmt.Sprintf("Could not parse URL for GitLab instance %q: %s", gl.Url, err))
			continue // omit authz provider if could not parse URL
		}
		if !strings.HasSuffix(gl.PermissionsMatcher, "/*") && !strings.HasPrefix(gl.PermissionsMatcher, "*/") {
			seriousProblems = append(seriousProblems, fmt.Sprintf("GitLab connection %q should specify a `permissions.matcher` string starting with \"*/\" or ending with \"/*\".", gl.Url))
		}
		if innerMatcher := strings.TrimSuffix(strings.TrimPrefix(gl.PermissionsMatcher, "*/"), "/*"); strings.Contains(innerMatcher, "*") {
			seriousProblems = append(seriousProblems, fmt.Sprintf("GitLab connection %q `permission.matcher` includes an interior wildcard \"*\", which will be interpreted as a string literal, rather than a pattern matcher. Only the prefix \"*/\" or the suffix \"/*\" is supported for pattern matching.", gl.Url))
		}

		ttl, err := time.ParseDuration(gl.PermissionsTtl)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Could not parse time duration %q, falling back to 24 hours.", gl.PermissionsTtl))
			ttl = time.Hour * 24
		}

		if mockNewGitLabAuthzProvider != nil {
			authzProviders = append(authzProviders,
				mockNewGitLabAuthzProvider(glURL, gl.Token, gl.RepositoryPathPattern, gl.PermissionsMatcher, ttl, nil))
		} else {
			authzProviders = append(authzProviders,
				permgl.NewGitLabAuthzProvider(glURL, gl.Token, gl.RepositoryPathPattern, gl.PermissionsMatcher, ttl, nil))
		}
	}

	return permissionsAllowByDefault, authnProviders, authzProviders, identityMappers, seriousProblems, warnings
}

func configHasOnlyExternalAuth(cfg *schema.SiteConfiguration) bool {
	for _, p := range cfg.AuthProviders {
		if p.Saml == nil && p.Openidconnect == nil && p.HttpHeader == nil {
			return false
		}
	}
	return true
}

var mockNewGitLabAuthzProvider func(baseURL *url.URL, sudoToken, repoPathPattern, matchPattern string, ttl time.Duration, cache interface{}) perm.AuthzProvider
