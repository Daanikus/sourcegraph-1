package perm

import (
	"context"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/perm"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
)

func Test_GitLab_RepoPerms(t *testing.T) {
	gitlabMock := mockGitLab{
		acls: map[perm.AuthzID][]string{
			"bl": []string{"bl/repo-1", "bl/repo-2", "bl/repo-3", "org/repo-1", "org/repo-2", "org/repo-3", "bl/a"},
			"kl": []string{"kl/repo-1", "kl/repo-2", "kl/repo-3"},
		},
		projs: map[string]*gitlab.Project{
			"bl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-1"}},
			"bl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-2"}},
			"bl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-3"}},
			"kl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-1"}},
			"kl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-2"}},
			"kl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-3"}},
			"org/repo-1": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-1"}},
			"org/repo-2": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-2"}},
			"org/repo-3": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-3"}},
			"bl/a":       &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/a"}},
		},
		t:          t,
		maxPerPage: 1,
	}
	gitlab.MockListProjects = gitlabMock.ListProjects

	tests := []struct {
		description  string
		gitlabURL    string
		matchPattern string
		authzID      perm.AuthzID
		repos        map[perm.Repo]struct{}
		expPerms     map[api.RepoURI]map[perm.P]bool
	}{{
		description:  "matchPattern enforces bl's perms (short input list)",
		gitlabURL:    "https://gitlab.mine",
		matchPattern: "gitlab.mine/*",
		authzID:      perm.AuthzID("bl"),
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/org/repo-1"}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expPerms: map[api.RepoURI]map[perm.P]bool{
			"gitlab.mine/bl/repo-1":  map[perm.P]bool{perm.Read: true},
			"gitlab.mine/kl/repo-1":  map[perm.P]bool{},
			"gitlab.mine/org/repo-1": map[perm.P]bool{perm.Read: true},
		},
	}, {
		description:  "matchPattern enforces kl's perms (short input list)",
		gitlabURL:    "https://gitlab.mine",
		matchPattern: "gitlab.mine/*",
		authzID:      perm.AuthzID("kl"),
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/org/repo-1"}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expPerms: map[api.RepoURI]map[perm.P]bool{
			"gitlab.mine/bl/repo-1":  map[perm.P]bool{},
			"gitlab.mine/kl/repo-1":  map[perm.P]bool{perm.Read: true},
			"gitlab.mine/org/repo-1": map[perm.P]bool{},
		},
	}, {
		description:  "matchPattern enforces bl's perms (long input list)",
		gitlabURL:    "https://gitlab.mine",
		matchPattern: "gitlab.mine/*",
		authzID:      perm.AuthzID("bl"),
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/repo-2"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/repo-3"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-2"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-3"}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expPerms: map[api.RepoURI]map[perm.P]bool{
			"gitlab.mine/bl/repo-1": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/bl/repo-2": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/bl/repo-3": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/kl/repo-1": map[perm.P]bool{},
			"gitlab.mine/kl/repo-2": map[perm.P]bool{},
			"gitlab.mine/kl/repo-3": map[perm.P]bool{},
		},
	}, {
		description:  "no matchPattern, use external repo spec",
		gitlabURL:    "https://gitlab.mine",
		matchPattern: "",
		authzID:      perm.AuthzID("bl"),
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/repo-2"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/repo-3"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-2"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-3"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "gitlab.mine/a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://not-mine/",
			}}: struct{}{},
			perm.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "not-gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expPerms: map[api.RepoURI]map[perm.P]bool{
			"gitlab.mine/bl/a": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/a":    map[perm.P]bool{},
			"a":                map[perm.P]bool{},
		},
	}, {
		description:  "matchPattern should take precendence over external repo spec",
		gitlabURL:    "https://gitlab.mine",
		matchPattern: "gitlab.mine/*",
		authzID:      perm.AuthzID("bl"),
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/repo-2"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/repo-3"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-2"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-3"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/bl/a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "gitlab.mine/a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://not-mine/",
			}}: struct{}{},
			perm.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "not-gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expPerms: map[api.RepoURI]map[perm.P]bool{
			"gitlab.mine/bl/repo-1": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/bl/repo-2": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/bl/repo-3": map[perm.P]bool{perm.Read: true},
			"gitlab.mine/bl/a":      map[perm.P]bool{perm.Read: true},
			"gitlab.mine/kl/repo-1": map[perm.P]bool{},
			"gitlab.mine/kl/repo-2": map[perm.P]bool{},
			"gitlab.mine/kl/repo-3": map[perm.P]bool{},
			"gitlab.mine/a":         map[perm.P]bool{},
		},
	}}

	for _, test := range tests {
		t.Logf("Test case %q", test.description)
		glURL, err := url.Parse(test.gitlabURL)
		if err != nil {
			t.Fatal(err)
		}

		// Create a new authz provider every time, so the cache is clear
		ctx := context.Background()
		authzProvider := NewGitLabAuthzProvider(glURL, "", "", test.matchPattern, 24*time.Hour, make(mockCache))

		perms, err := authzProvider.RepoPerms(ctx, test.authzID, test.repos)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(perms, test.expPerms) {
			t.Errorf("Expected perms %+v, but got %+v", test.expPerms, perms)
		}
	}
}

func Test_GitLab_RepoPerms_cache(t *testing.T) {
	gitlabMock := mockGitLab{
		acls: map[perm.AuthzID][]string{
			"bl": []string{"bl/repo-1", "bl/repo-2", "bl/repo-3", "org/repo-1", "org/repo-2", "org/repo-3"},
			"kl": []string{"kl/repo-1", "kl/repo-2", "kl/repo-3"},
		},
		projs: map[string]*gitlab.Project{
			"bl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-1"}},
			"bl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-2"}},
			"bl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-3"}},
			"kl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-1"}},
			"kl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-2"}},
			"kl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-3"}},
			"org/repo-1": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-1"}},
			"org/repo-2": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-2"}},
			"org/repo-3": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-3"}},
		},
		t:          t,
		maxPerPage: 100,
	}
	gitlab.MockListProjects = gitlabMock.ListProjects

	glURL, err := url.Parse("https://gitlab.mine")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	authzProvider := NewGitLabAuthzProvider(glURL, "", "", "gitlab.mine/*", 0, make(mockCache))
	if _, err := authzProvider.RepoPerms(ctx, "bl", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := authzProvider.RepoPerms(ctx, "bl", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := authzProvider.RepoPerms(ctx, "bl", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := authzProvider.RepoPerms(ctx, "kl", nil); err != nil {
		t.Fatal(err)
	}

	expMadeRequests := map[string]int{
		"projects?per_page=100&sudo=bl": 1,
		"projects?per_page=100&sudo=kl": 1,
	}
	if !reflect.DeepEqual(gitlabMock.madeRequests, expMadeRequests) {
		t.Errorf("Unexpected cache behavior. Expected underying requests to be %#v, but got %#v", expMadeRequests, gitlabMock.madeRequests)
	}
}

func Test_GitLab_Repos(t *testing.T) {
	tests := []struct {
		matchPattern string
		repos        map[perm.Repo]struct{}
		expMine      map[perm.Repo]struct{}
		expOthers    map[perm.Repo]struct{}
	}{{
		matchPattern: "gitlab.mine/*",
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
			perm.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expMine: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
		},
		expOthers: map[perm.Repo]struct{}{
			perm.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
	}, {
		matchPattern: "",
		repos: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
			perm.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
			perm.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://not-mine/",
			}}: struct{}{},
			perm.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "not-gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expMine: map[perm.Repo]struct{}{
			perm.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expOthers: map[perm.Repo]struct{}{
			perm.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
			perm.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
			perm.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
			perm.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://not-mine/",
			}}: struct{}{},
			perm.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "not-gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
	}}

	for _, test := range tests {
		glURL, err := url.Parse("https://gitlab.mine")
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		authzProvider := NewGitLabAuthzProvider(glURL, "", "", test.matchPattern, 0, make(mockCache))
		mine, others := authzProvider.Repos(ctx, test.repos)
		if !reflect.DeepEqual(mine, test.expMine) {
			t.Errorf("For match pattern %q, expected mine to be %v, but got %v", test.matchPattern, test.expMine, mine)
		}
		if !reflect.DeepEqual(others, test.expOthers) {
			t.Errorf("For match pattern %q, expected others to be %v, but got %v", test.matchPattern, test.expOthers, others)
		}
	}
}

// mockGitLab is a mock for the GitLab client that can be used by tests. Instantiating a mockGitLab
// instance itself does nothing, but its methods can be used to replace the mock functions (e.g.,
// MockListProjects).
//
// We prefer to do it this way, instead of defining an interface for the GitLab client, because this
// preserves the ability to jump-to-def around the actual implementation.
type mockGitLab struct {
	acls         map[perm.AuthzID][]string
	projs        map[string]*gitlab.Project
	t            *testing.T
	maxPerPage   int
	madeRequests map[string]int
}

func (m *mockGitLab) ListProjects(ctx context.Context, urlStr string) (proj []*gitlab.Project, nextPageURL *string, err error) {
	if m.madeRequests == nil {
		m.madeRequests = make(map[string]int)
	}
	m.madeRequests[urlStr]++

	u, err := url.Parse(urlStr)
	if err != nil {
		m.t.Fatalf("could not parse ListProjects urlStr %q: %s", urlStr, err)
	}
	repoNames := m.acls[perm.AuthzID(u.Query().Get("sudo"))]
	allProjs := make([]*gitlab.Project, len(repoNames))
	for i, repoName := range repoNames {
		proj, ok := m.projs[repoName]
		if !ok {
			m.t.Fatalf("Dangling project reference in mockGitLab: %s", repoName)
		}
		allProjs[i] = proj
	}

	perPage, err := getIntOrDefault(u.Query().Get("per_page"), m.maxPerPage)
	if err != nil {
		return nil, nil, err
	}
	if perPage > m.maxPerPage {
		perPage = m.maxPerPage
	}
	pg, err := getIntOrDefault(u.Query().Get("page"), 1)
	if err != nil {
		return nil, nil, err
	}
	p := pg - 1
	var (
		pageProjs []*gitlab.Project
	)
	if perPage*p > len(allProjs)-1 {
		pageProjs = nil
	} else if perPage*(p+1) > len(allProjs)-1 {
		pageProjs = allProjs[perPage*p:]
	} else {
		pageProjs = allProjs[perPage*p : perPage*(p+1)]
		if perPage*(p+1) <= len(allProjs)-1 {
			newU := *u
			q := u.Query()
			q.Set("page", strconv.Itoa(pg+1))
			newU.RawQuery = q.Encode()
			s := newU.String()
			nextPageURL = &s
		}
	}
	return pageProjs, nextPageURL, nil
}

type mockCache map[string]string

func (m mockCache) Get(key string) ([]byte, bool) { v, ok := m[key]; return []byte(v), ok }
func (m mockCache) Set(key string, b []byte)      { m[key] = string(b) }
func (m mockCache) Delete(key string)             { delete(m, key) }

func getIntOrDefault(str string, def int) (int, error) {
	if str == "" {
		return def, nil
	}
	return strconv.Atoi(str)
}
