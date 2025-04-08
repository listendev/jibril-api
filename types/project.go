package types

import (
	"time"

	"github.com/listendev/jibril-api/types/errs"
)

const (
	ErrUnauthorizedProject = errs.UnauthorizedError("permission denied")
	ErrInvalidProjectName  = errs.InvalidArgumentError("invalid project name")
	ErrProjectExists       = errs.ConflictError("project with this name already exists in this organization")
	MaxProjectNameLength   = 128
)

// Project represents a project in the system.
type Project struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    *string   `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CreateProject represents the data needed to create a new project.
type CreateProject struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

func (c *CreateProject) Validate() error {
	if c.Name == "" {
		return ErrInvalidProjectName
	}

	if len(c.Name) > MaxProjectNameLength {
		return ErrInvalidProjectName
	}

	return nil
}

// ProjectCreated represents the response after a project is created.
type ProjectCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// UpdateProject represents the data needed to update an existing project.
type UpdateProject struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

func (u *UpdateProject) Validate() error {
	if u.Name == nil && u.Description == nil {
		return errs.ErrInvalidArgument
	}

	if u.Name != nil {
		if *u.Name == "" {
			return ErrInvalidProjectName
		}

		if len(*u.Name) > MaxProjectNameLength {
			return ErrInvalidProjectName
		}
	}

	return nil
}

// ProjectUpdated represents the response after a project is updated.
type ProjectUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListProjects represents the query parameters for listing projects.
type ListProjects struct {
	OrganizationID string `json:"organization_id,omitempty"`
	PageArgs
}

// ListUserProjects represents the query parameters for listing projects a user has access to.
type ListUserProjects struct {
	UserID string `json:"user_id"`
	PageArgs
}

// ProjectCounters represents the count of repositories and workflows in a project.
type ProjectCounters struct {
	RepositoryCount int `json:"repository_count"`
	WorkflowCount   int `json:"workflow_count"`
}
