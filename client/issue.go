package client

import (
	"context"
	"net/http"

	"github.com/listendev/jibril-server/types"
)

// CreateIssue creates a new issue with the given params.
func (c *Client) CreateIssue(ctx context.Context, issue types.CreateIssue) (types.IssueCreated, error) {
	var out types.IssueCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/issues", issue)
}

// GetIssue retrieves an issue by ID.
func (c *Client) GetIssue(ctx context.Context, issueID string) (types.Issue, error) {
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
