package gitlab

import (
	"context"
)

// MockListProjects, if non-nil, will be called instead of every invocation of Client.ListProjects.
var MockListProjects func(ctx context.Context, urlStr string) (proj []*Project, nextPageURL *string, err error)
