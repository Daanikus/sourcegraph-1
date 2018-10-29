package shared

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/auth"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	permgl "github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm/gitlab"
	"github.com/sourcegraph/sourcegraph/pkg/conf"
	"github.com/sourcegraph/sourcegraph/schema"
	log15 "gopkg.in/inconshreveable/log15.v2"
)

func init() {
	conf.ContributeValidator(func(cfg schema.SiteConfiguration) []string {
		_, _, seriousProblems, warnings := providersFromConfig(&cfg)
		return append(seriousProblems, warnings...)
	})
	conf.Watch(func() {
		permissionsAllowByDefault, authzProviders, _, _ := providersFromConfig(conf.Get())
		perm.SetProviders(permissionsAllowByDefault, nil, authzProviders, nil)
	})
}

// providersFromConfig returns the set of permission-related providers derived from the site config.
// It also returns any validation problems with the config, separating these into "serious problems"
// and "warnings".  "Serious problems" are those that should make Sourcegraph set
// perm.permissionsAllowByDefault to false. "Warnings" are all other validation problems.
func providersFromConfig(cfg *schema.SiteConfiguration) (
	permissionsAllowByDefault bool,
	authzProviders []perm.AuthzProvider,
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

	// Authorization (i.e., permissions) providers
	for _, gl := range cfg.Gitlab {
		if gl.Authz == nil {
			continue
		}

		// TODO: any more warnings (e.g., missing identityServiceID) when permissions are enabled?

		glURL, err := url.Parse(gl.Url)
		if err != nil {
			seriousProblems = append(seriousProblems, fmt.Sprintf("Could not parse URL for GitLab instance %q: %s", gl.Url, err))
			continue // omit authz provider if could not parse URL
		}
		if innerMatcher := strings.TrimSuffix(strings.TrimPrefix(gl.Authz.Matcher, "*/"), "/*"); strings.Contains(innerMatcher, "*") {
			seriousProblems = append(seriousProblems, fmt.Sprintf("GitLab connection %q `permission.matcher` includes an interior wildcard \"*\", which will be interpreted as a string literal, rather than a pattern matcher. Only the prefix \"*/\" or the suffix \"/*\" is supported for pattern matching.", gl.Url))
		}

		var ttl time.Duration
		if gl.Authz.Ttl == "" {
			ttl = time.Hour * 3
		} else {
			ttl, err = time.ParseDuration(gl.Authz.Ttl)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Could not parse time duration %q, falling back to 3 hours.", gl.Authz.Ttl))
				ttl = time.Hour * 3
			}
		}

		op := permgl.GitLabAuthzProviderOp{
			BaseURL:                  glURL,
			SudoToken:                gl.Token,
			RepoPathPattern:          gl.RepositoryPathPattern,
			MatchPattern:             gl.Authz.Matcher,
			GitLabIdentityProviderID: gl.Authz.AuthnGitLabProvider,
			CacheTTL:                 ttl,
			MockCache:                nil,
		}
		if gl.Authz.AuthnConfigID == "" {
			// If no authn provider is specified, we fall back to insecure username matching, which
			// should only be used for testing purposes. In the future when we support sign-in via
			// GitLab, we can check if that is enabled and instead fall back to that.
			seriousProblems = append(seriousProblems, "`authz.AuthnConfigID` was not specified. Falling back to using username matching, which is insecure.")
			op.UseNativeUsername = true
		} else if gl.Authz.AuthnGitLabProvider == "" {
			seriousProblems = append(seriousProblems, "`authz.AuthnGitLabProvider` was not specified, which means GitLab users cannot be resolved.")
		} else {
			if authnProvider := findAuthnProvider(gl.Authz.AuthnConfigID); authnProvider != nil {
				op.IdentityServiceType = authnProvider.ConfigID().Type
				op.IdentityServiceID = authnProvider.CachedInfo().ServiceID
			} else {
				seriousProblems = append(seriousProblems, fmt.Sprintf("Could not find item in `auth.providers` with config ID %q", gl.Authz.AuthnConfigID))
			}
		}

		authzProviders = append(authzProviders, NewGitLabAuthzProvider(op))
	}

	return permissionsAllowByDefault, authzProviders, seriousProblems, warnings
}

func findAuthnProvider(configID string) auth.Provider {
	for _, authnProvider := range auth.Providers() {
		if authnProvider.CachedInfo().ConfigID == configID {
			return authnProvider
		}
	}
	return nil
}

// NewGitLabAuthzProvider is a mockable constructor for new GitLabAuthzProvider instances.
var NewGitLabAuthzProvider = func(op permgl.GitLabAuthzProviderOp) perm.AuthzProvider {
	return permgl.NewGitLabAuthzProvider(op)
}
