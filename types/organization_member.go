package types

import (
	"time"

	"github.com/listendev/jibril-api/types/errs"
)

const (
	ErrUnauthorizedOrganizationMember = errs.UnauthorizedError("permission denied")
	ErrOrganizationMemberNotFound     = errs.NotFoundError("organization member not found")
)

// OrganizationMember represents a user's membership in an organization.
type OrganizationMember struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	OrganizationID string     `json:"organization_id"`
	IsAdmin        bool       `json:"is_admin"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"-"`

	User         *User         `json:"user,omitempty"`
	Organization *Organization `json:"organization,omitempty"`
}

// CreateOrganizationMember represents the request to create a new organization member.
type CreateOrganizationMember struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
}

// OrganizationMemberCreated represents the response after an organization member is created.
type OrganizationMemberCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Validate validates the CreateOrganizationMember input.
func (c *CreateOrganizationMember) Validate() error {
	if c.UserID == "" {
		return ErrUserIDRequired
	}

	return nil
}

// UpdateOrganizationMember represents the request to update an existing organization member.
type UpdateOrganizationMember struct {
	IsAdmin *bool `json:"is_admin,omitempty"`
}

// OrganizationMemberUpdated represents the response after an organization member is updated.
type OrganizationMemberUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate validates the UpdateOrganizationMember input.
func (u *UpdateOrganizationMember) Validate() error {
	if u.IsAdmin == nil {
		return errs.ErrInvalidArgument
	}

	return nil
}

// ListOrganizationMembers represents the query parameters for listing organization members.
type ListOrganizationMembers struct {
	OrganizationID string `json:"organization_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	PageArgs
}
