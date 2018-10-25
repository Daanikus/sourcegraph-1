package gitlab

import (
	"net/url"
	"strconv"

	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/externalservice"
)

// GitLabServiceType is the (api.ExternalRepoSpec).ServiceType value for GitLab projects. The ServiceID value is
// the base URL to the GitLab instance (https://gitlab.com or self-hosted GitLab URL).
const GitLabServiceType = "gitlab"

// GitLabExternalRepoSpec returns an api.ExternalRepoSpec that refers to the specified GitLab project.
func GitLabExternalRepoSpec(proj *Project, baseURL url.URL) *api.ExternalRepoSpec {
	return &api.ExternalRepoSpec{
		ID:          strconv.Itoa(proj.ID),
		ServiceType: GitLabServiceType,
		ServiceID:   externalservice.NormalizeBaseURL(&baseURL).String(),
	}
}

type CodeHost struct {
	id string
}

func NewCodeHost(baseURL *url.URL) *CodeHost {
	return &CodeHost{id: externalservice.NormalizeBaseURL(baseURL).String()}
}

func (h *CodeHost) IsHostOf(repo *api.ExternalRepoSpec) bool {
	return GitLabServiceType == repo.ServiceType && repo.ServiceID == h.id
}
