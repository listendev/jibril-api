package types

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/listendev/jibril-server/types/errs"
)

// Issue state and priority constants.
const (
	IssueStateTriaged IssueState = "triaged"
	IssueStateIgnored IssueState = "ignored"
	IssueStateBlocked IssueState = "blocked"

	IssuePriorityLow      IssuePriority = "low"
	IssuePriorityMedium   IssuePriority = "medium"
	IssuePriorityHigh     IssuePriority = "high"
	IssuePriorityCritical IssuePriority = "critical"
)

const (
	ErrInvalidIssueState       = errs.InvalidArgumentError("invalid issue state")
	ErrInvalidIssuePriority    = errs.InvalidArgumentError("invalid issue priority")
	ErrInvalidIssueClass       = errs.InvalidArgumentError("invalid issue class")
	ErrInvalidIssueDescription = errs.InvalidArgumentError("invalid issue description")
	ErrInvalidIssueEventIDs    = errs.InvalidArgumentError("invalid issue event IDs")
	ErrInvalidIssueIgnoreFor   = errs.InvalidArgumentError("invalid issue ignore_for")
	ErrInvalidIssueReason      = errs.InvalidArgumentError("invalid issue reason")
	ErrUnauthorizedEvents      = errs.UnauthorizedError("one or more events do not belong to this project")
)

// IssueState represents the possible states of an issue.
type IssueState string

func (s IssueState) String() string {
	return string(s)
}

func (s IssueState) IsValid() bool {
	switch s {
	case IssueStateTriaged, IssueStateIgnored, IssueStateBlocked:
		return true
	}
	return false
}

// IssuePriority represents the possible priority levels of an issue.
type IssuePriority string

func (p IssuePriority) String() string {
	return string(p)
}

func (p IssuePriority) IsValid() bool {
	switch p {
	case IssuePriorityLow, IssuePriorityMedium, IssuePriorityHigh, IssuePriorityCritical:
		return true
	}
	return false
}

// IssueLabels represents a typed map of labels.
type IssueLabels map[string]string

// UnmarshalJSON implements custom JSON unmarshaling for IssueLabels.
func (l *IssueLabels) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*l = make(IssueLabels)
		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	*l = m
	return nil
}

// Scan implements sql.Scanner interface.
func (l *IssueLabels) Scan(value interface{}) error {
	if value == nil {
		*l = make(IssueLabels)
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, l)
	case string:
		return json.Unmarshal([]byte(v), l)
	default:
		return fmt.Errorf("unsupported type for IssueLabels: %T", value)
	}
}

// The format is: label.key=value (e.g., label.severity=high).
func (l *IssueLabels) Encode() url.Values {
	values := url.Values{}

	if l == nil {
		return values
	}

	for key, value := range *l {
		values.Set("label."+key, value)
	}

	return values
}

// DecodeIssueLabels extracts IssueLabels from URL query parameters.
func DecodeIssueLabels(values url.Values) IssueLabels {
	labels := IssueLabels{}

	prefix := "label."
	for key, vals := range values {
		if len(vals) > 0 && len(key) > len(prefix) && key[:len(prefix)] == prefix {
			labelKey := key[len(prefix):]
			labels[labelKey] = vals[0]
		}
	}

	return labels
}

// Issue represents the stored issue model.
type Issue struct {
	ID          string        `db:"id"          json:"id"`
	ProjectID   string        `db:"project_id"  json:"-"` // Not exposed in API
	Class       string        `db:"class"       json:"class"`
	Description string        `db:"description" json:"description"`
	State       IssueState    `db:"state"       json:"state"`
	Priority    IssuePriority `db:"priority"    json:"priority"`
	Labels      IssueLabels   `db:"labels"      json:"labels"`
	IgnoreFor   string        `db:"ignore_for"  json:"ignore_for,omitempty"`
	Events      []Event       `db:"-"           json:"events"` // No omitempty
	CreatedAt   time.Time     `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time     `db:"updated_at"  json:"updated_at"`
	DeletedAt   *time.Time    `db:"deleted_at"  json:"deleted_at,omitempty"`
}

// CreateIssue represents the request to create a new issue.
type CreateIssue struct {
	Class       string        `json:"class"`
	Description string        `json:"description"`
	State       IssueState    `json:"state"`
	Priority    IssuePriority `json:"priority"`
	Labels      IssueLabels   `json:"labels"`
	EventIDs    []string      `json:"event_ids"`
}

func (c *CreateIssue) Validate() error {
	// Check issue state
	if !c.State.IsValid() {
		return ErrInvalidIssueState
	}

	// Check issue priority
	if !c.Priority.IsValid() {
		return ErrInvalidIssuePriority
	}

	// Check required fields
	if c.Class == "" {
		return ErrInvalidIssueClass
	}

	if c.Description == "" {
		return ErrInvalidIssueDescription
	}

	if len(c.EventIDs) == 0 {
		return ErrInvalidIssueEventIDs
	}

	return nil
}

// IssueCreated represents the response when an issue is successfully created.
type IssueCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateIssue represents the request to update an existing issue.
type UpdateIssue struct {
	Class       *string        `json:"class,omitempty"`
	Description *string        `json:"description,omitempty"`
	State       *IssueState    `json:"state,omitempty"`
	Priority    *IssuePriority `json:"priority,omitempty"`
	Labels      *IssueLabels   `json:"labels,omitempty"`
	IgnoreFor   *string        `json:"ignore_for,omitempty"`
	Reason      *string        `json:"reason,omitempty"`    // Reason for state change
	EventIDs    []string       `json:"event_ids,omitempty"` // Event IDs to add to the issue
}

func (u *UpdateIssue) Validate() error {
	// Check if any fields are specified
	if u.Class == nil && u.Description == nil && u.State == nil &&
		u.Priority == nil && u.Labels == nil && u.IgnoreFor == nil &&
		u.Reason == nil && len(u.EventIDs) == 0 {
		return errs.InvalidArgumentError("at least one field is required")
	}

	// Validate class if provided
	if u.Class != nil && *u.Class == "" {
		return ErrInvalidIssueClass
	}

	// Validate description if provided
	if u.Description != nil && *u.Description == "" {
		return ErrInvalidIssueDescription
	}

	// Validate state if provided
	if u.State != nil && !u.State.IsValid() {
		return ErrInvalidIssueState
	}

	// Validate priority if provided
	if u.Priority != nil && !u.Priority.IsValid() {
		return ErrInvalidIssuePriority
	}

	// If state is being changed to ignored, ensure ignore_for is provided
	if u.State != nil && *u.State == IssueStateIgnored &&
		(u.IgnoreFor == nil || *u.IgnoreFor == "") {
		return ErrInvalidIssueIgnoreFor
	}

	// If state is being changed, require a reason
	if u.State != nil && (u.Reason == nil || *u.Reason == "") {
		return ErrInvalidIssueReason
	}

	return nil
}

// IssueUpdated represents the response when an issue is successfully updated.
type IssueUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}
