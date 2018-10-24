package perm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/conf/reposource"
	"github.com/sourcegraph/sourcegraph/pkg/externalservice/gitlab"
	"github.com/sourcegraph/sourcegraph/pkg/rcache"
	log15 "gopkg.in/inconshreveable/log15.v2"
)

type pcache interface {
	Get(key string) ([]byte, bool)
	Set(key string, b []byte)
	Delete(key string)
}

type GitLabAuthzProvider struct {
	client          *gitlab.Client
	clientURL       *url.URL
	codeHost        *gitlab.CodeHost
	repoPathPattern string
	cache           pcache

	// matchPattern, if non-empty, should be a string that may contain a prefix "*/" or suffix "/*".
	// If it satisfies neither, *no* repositories will be matched.  If empty, we match on the value
	// of ExternalRepoSpec (fetched from the DB).
	matchPattern string
}

type cacheVal struct {
	// repos is the list of repositories to which the user has access.
	repos map[api.RepoURI]struct{}
}

func NewGitLabAuthzProvider(baseURL *url.URL, sudoToken, repoPathPattern, matchPattern string, cacheTTL time.Duration, mockCache pcache) *GitLabAuthzProvider {
	p := &GitLabAuthzProvider{
		client:          gitlab.NewClient(baseURL, sudoToken, nil),
		clientURL:       baseURL,
		codeHost:        gitlab.NewCodeHost(baseURL),
		repoPathPattern: repoPathPattern,
		matchPattern:    matchPattern,
		cache:           mockCache,
	}
	if p.cache == nil {
		p.cache = rcache.NewWithTTL(fmt.Sprintf("gitlabAuthz:%s", baseURL.String()), int(math.Ceil(cacheTTL.Seconds())))
	}
	return p
}

func (p *GitLabAuthzProvider) RepoPerms(ctx context.Context, authzID perm.AuthzID, repos map[perm.Repo]struct{}) (map[api.RepoURI]map[perm.P]bool, error) {
	myRepos, _ := p.Repos(ctx, repos)
	var accessibleRepos map[api.RepoURI]struct{}
	if r, exists := p.getCachedAccessList(authzID); exists {
		accessibleRepos = r
	} else {
		var err error
		accessibleRepos, err = p.fetchUserAccessList(ctx, authzID)
		if err != nil {
			return nil, err
		}

		accessibleReposB, err := json.Marshal(cacheVal{repos: accessibleRepos})
		if err != nil {
			return nil, err
		}
		p.cache.Set(string(authzID), accessibleReposB)
	}

	perms := make(map[api.RepoURI]map[perm.P]bool)
	for repo := range myRepos {
		if _, ok := accessibleRepos[repo.URI]; ok {
			perms[repo.URI] = map[perm.P]bool{perm.Read: true}
		} else {
			perms[repo.URI] = map[perm.P]bool{}
		}
	}
	return perms, nil
}

func (p *GitLabAuthzProvider) Repos(ctx context.Context, repos map[perm.Repo]struct{}) (mine map[perm.Repo]struct{}, others map[perm.Repo]struct{}) {
	if p.matchPattern != "" {
		if mt, matchString, err := ParseMatchPattern(p.matchPattern); err == nil {
			if mine, others, err = reposByMatchPattern(mt, matchString, repos); err == nil {
				return mine, others
			} else {
				log15.Error("Unexpected error executing matchPattern", "matchPattern", p.matchPattern, "err", err)
			}
		} else {
			log15.Error("Error parsing matchPattern", "err", err)
		}
	}

	mine, others = make(map[perm.Repo]struct{}), make(map[perm.Repo]struct{})
	for repo := range repos {
		if p.codeHost.IsHostOf(&repo.ExternalRepoSpec) {
			mine[repo] = struct{}{}
		} else {
			others[repo] = struct{}{}
		}
	}
	return mine, others
}

func reposByMatchPattern(mt matchType, matchString string, repos map[perm.Repo]struct{}) (mine map[perm.Repo]struct{}, others map[perm.Repo]struct{}, err error) {
	mine, others = make(map[perm.Repo]struct{}), make(map[perm.Repo]struct{})
	for repo := range repos {
		switch mt {
		case matchSubstring:
			if strings.Contains(string(repo.URI), matchString) {
				mine[repo] = struct{}{}
			} else {
				others[repo] = struct{}{}
			}
		case matchPrefix:
			if strings.HasPrefix(string(repo.URI), matchString) {
				mine[repo] = struct{}{}
			} else {
				others[repo] = struct{}{}
			}
		case matchSuffix:
			if strings.HasSuffix(string(repo.URI), matchString) {
				mine[repo] = struct{}{}
			} else {
				others[repo] = struct{}{}
			}
		default:
			return nil, nil, fmt.Errorf("Unrecognized matchType: %v", mt)
		}
	}
	return mine, others, nil
}

func (p *GitLabAuthzProvider) getCachedAccessList(authzID perm.AuthzID) (map[api.RepoURI]struct{}, bool) {

	// TODO(beyang): trigger best-effort fetch in background if ttl is getting close (but avoid dup refetches)

	cachedReposB, exists := p.cache.Get(string(authzID))
	if !exists {
		return nil, exists
	}
	var r cacheVal
	if err := json.Unmarshal(cachedReposB, &r); err != nil {
		log15.Warn("Failed to unmarshal repo perm cache entry: %s", err.Error())
		return nil, false
	}
	return r.repos, true
}

// fetchUserAccessList fetches the list of repositories that are readable to a user from the GitLab API.
func (p *GitLabAuthzProvider) fetchUserAccessList(ctx context.Context, authzID perm.AuthzID) (map[api.RepoURI]struct{}, error) {
	q := make(url.Values)
	q.Add("sudo", string(authzID))
	q.Add("per_page", "100")

	var allProjs []*gitlab.Project
	var iters = 0
	var pageURL = "projects?" + q.Encode()
	for {
		if iters >= 100 && iters%100 == 0 {
			log15.Warn("Excessively many GitLab API requests to fetch complete user authz list", "iters", iters, "authzID", authzID, "host", p.clientURL.String())
		}

		projs, nextPageURL, err := p.client.ListProjects(ctx, pageURL)
		if err != nil {
			return nil, err
		}

		allProjs = append(allProjs, projs...)
		if nextPageURL == nil {
			break
		}
		pageURL = *nextPageURL
		iters++
	}

	accessibleRepos := make(map[api.RepoURI]struct{})
	for _, proj := range allProjs {
		repoURI := reposource.GitLabRepoURI(p.repoPathPattern, p.clientURL.Hostname(), proj.PathWithNamespace)
		accessibleRepos[repoURI] = struct{}{}
	}
	return accessibleRepos, nil
}

type matchType string

const (
	matchPrefix    matchType = "prefix"
	matchSuffix              = "suffix"
	matchSubstring           = "substring"
)

func ParseMatchPattern(matchPattern string) (mt matchType, matchString string, err error) {
	startGlob := strings.HasPrefix(matchPattern, "*/")
	endGlob := strings.HasSuffix(matchPattern, "/*")
	matchString = strings.TrimPrefix(strings.TrimSuffix(matchPattern, "/*"), "*/")

	switch {
	case startGlob && endGlob:
		return matchSubstring, "/" + matchString + "/", nil
	case startGlob:
		return matchSuffix, "/" + matchString, nil
	case endGlob:
		return matchPrefix, matchString + "/", nil
	default:
		// If no wildcard, then match no repositories
		return "", "", errors.New("matchPattern should start with \"*/\" or end with \"/*\"")
	}
}
