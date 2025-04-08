package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/listendev/jibril-api/types"
)

// CreateIssue creates a new issue with the given params.
func (c *Client) CreateIssue(ctx context.Context, issue types.CreateIssue) (types.IssueCreated, error) {
	var out types.IssueCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/issues", issue)
}

// Issue retrieves an issue by ID.
func (c *Client) Issue(ctx context.Context, issueID string) (types.Issue, error) {
	var out types.Issue

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/issues/"+issueID, nil)
}

// DeleteIssue soft-deletes an issue by ID.
func (c *Client) DeleteIssue(ctx context.Context, issueID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/issues/"+issueID, nil)
}

// UpdateIssue updates specific fields of an issue.
func (c *Client) UpdateIssue(ctx context.Context, issueID string, issue types.UpdateIssue) (types.IssueUpdated, error) {
	var out types.IssueUpdated

	return out, c.do(ctx, &out, http.MethodPatch, "/api/v1/issues/"+issueID, issue)
}

// Issues retrieves a list of issues based on the provided filters and pagination parameters.
func (c *Client) Issues(ctx context.Context, params types.ListIssues) (types.Page[types.Issue], error) {
	var out types.Page[types.Issue]

	// Build query parameters
	query := url.Values{}

	// Add filter parameters if provided
	if params.Filters != nil {
		if params.Filters.Class != nil {
			query.Set("filter.class", params.Filters.Class.String())
		}
		if params.Filters.State != nil {
			query.Set("filter.state", params.Filters.State.String())
		}
		if params.Filters.Priority != nil {
			query.Set("filter.priority", params.Filters.Priority.String())
		}
		if params.Filters.AgentKind != nil {
			query.Set("filter.agent_kind", params.Filters.AgentKind.String())
		}
		// Add the new filter parameters for repository and workflow
		if params.Filters.RepositoryID != nil {
			query.Set("filter.repository_id", *params.Filters.RepositoryID)
		}
		if params.Filters.Repository != nil {
			query.Set("filter.repository", *params.Filters.Repository)
		}
		if params.Filters.WorkflowName != nil {
			query.Set("filter.workflow_name", *params.Filters.WorkflowName)
		}
	}

	// Add label filters
	for key, value := range params.Labels {
		query.Set("label."+key, value)
	}

	// Add pagination parameters
	if params.PageArgs.First != nil {
		query.Set("first", strconv.FormatUint(uint64(*params.PageArgs.First), 10))
	}
	if params.PageArgs.Last != nil {
		query.Set("last", strconv.FormatUint(uint64(*params.PageArgs.Last), 10))
	}
	if params.PageArgs.After != nil {
		query.Set("after", string(*params.PageArgs.After))
	}
	if params.PageArgs.Before != nil {
		query.Set("before", string(*params.PageArgs.Before))
	}

	// Add include_ignored parameter if true
	if params.IncludeIgnored {
		query.Set("include_ignored", "true")
	}

	// Make the request
	url := "/api/v1/issues"
	if len(query) > 0 {
		url += "?" + query.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, url, nil)
}

// AllowIssue performs an allow action on an issue with the specified scope.
func (c *Client) AllowIssue(ctx context.Context, issueID string, action types.IssueAction) (types.IssueActionPerformed, error) {
	var out types.IssueActionPerformed

	// Force the action type to be "allow" regardless of what's provided
	action.ActionType = types.IssueActionTypeAllow

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/issues/"+issueID+"/actions/allow", action)
}

// BlockIssue performs a block action on an issue with the specified scope.
func (c *Client) BlockIssue(ctx context.Context, issueID string, action types.IssueAction) (types.IssueActionPerformed, error) {
	var out types.IssueActionPerformed

	// Force the action type to be "block" regardless of what's provided
	action.ActionType = types.IssueActionTypeBlock

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/issues/"+issueID+"/actions/block", action)
}

// IssueActionHistory retrieves the history of actions performed on an issue.
func (c *Client) IssueActionHistory(ctx context.Context, issueID string) ([]types.IssueActionHistory, error) {
	var out []types.IssueActionHistory

	url := "/api/v1/issues/" + issueID + "/actions"
	err := c.do(ctx, &out, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// IssueClasses retrieves all available and enabled issue classes.
func (c *Client) IssueClasses(ctx context.Context) ([]types.IssueClass, error) {
	var out []types.IssueClass

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/issue_classes", nil)
}
