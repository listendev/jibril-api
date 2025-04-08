package client

import (
	"context"
	"net/url"
	"strconv"

	"github.com/listendev/jibril-api/types"
)

// ProjectCounters retrieves the repository and workflow counts for a project.
func (c *Client) ProjectCounters(ctx context.Context) (types.ProjectCounters, error) {
	var result types.ProjectCounters
	err := c.do(ctx, &result, "GET", "/api/v1/project_counters", nil)
	if err != nil {
		return types.ProjectCounters{}, err
	}
	return result, nil
}

// CreateProjectSetting creates a new project setting.
func (c *Client) CreateProjectSetting(ctx context.Context, setting types.ProjectSettingCreate) (types.ProjectSettingCreated, error) {
	var out types.ProjectSettingCreated
	return out, c.do(ctx, &out, "POST", "/api/v1/project_settings", setting)
}

// ProjectSetting gets a specific project setting.
func (c *Client) ProjectSetting(ctx context.Context, key string) (types.ProjectSetting, error) {
	var out types.ProjectSetting
	path := "/api/v1/project_settings/" + url.PathEscape(key)
	return out, c.do(ctx, &out, "GET", path, nil)
}

// UpdateProjectSetting updates an existing project setting.
func (c *Client) UpdateProjectSetting(ctx context.Context, key string, update types.ProjectSettingUpdate) (types.ProjectSettingUpdated, error) {
	var out types.ProjectSettingUpdated
	path := "/api/v1/project_settings/" + url.PathEscape(key)
	return out, c.do(ctx, &out, "PATCH", path, update)
}

// DeleteProjectSetting deletes a project setting.
func (c *Client) DeleteProjectSetting(ctx context.Context, key string) error {
	path := "/api/v1/project_settings/" + url.PathEscape(key)
	return c.do(ctx, nil, "DELETE", path, nil)
}

// ProjectSettings lists all project settings.
func (c *Client) ProjectSettings(ctx context.Context, params *types.PageArgs) (types.Page[types.ProjectSetting], error) {
	var out types.Page[types.ProjectSetting]

	q := url.Values{}

	// Add pagination parameters
	if params != nil {
		if params.First != nil {
			q.Set("first", strconv.FormatUint(uint64(*params.First), 10))
		}
		if params.Last != nil {
			q.Set("last", strconv.FormatUint(uint64(*params.Last), 10))
		}
		if params.After != nil {
			q.Set("after", string(*params.After))
		}
		if params.Before != nil {
			q.Set("before", string(*params.Before))
		}
	}

	path := "/api/v1/project_settings"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, "GET", path, nil)
}
