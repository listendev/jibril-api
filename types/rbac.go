package types

import (
	"strings"
	"time"

	"github.com/listendev/jibril-api/types/errs"
)

const (
	ErrRoleNameRequired   = errs.InvalidArgumentError("role name is required")
	ErrRoleNotFound       = errs.NotFoundError("role not found")
	ErrMemberNotFound     = errs.NotFoundError("member not found")
	ErrInvalidPermission  = errs.InvalidArgumentError("invalid permission")
	ErrInvalidResource    = errs.InvalidArgumentError("invalid resource")
	ErrRoleIDRequired     = errs.InvalidArgumentError("role_id is required")
	ErrUserIDRequired     = errs.InvalidArgumentError("user_id is required")
	ErrMissingUpdateField = errs.InvalidArgumentError("at least one field to update is required")
	ErrUnauthorizedRole   = errs.UnauthorizedError("permission denied")
)

// Permission defines a permission string type.
type Permission string

const (
	// Operation permissions.
	PermCreate Permission = "create"
	PermRead   Permission = "read"
	PermUpdate Permission = "update"
	PermDelete Permission = "delete"
	PermList   Permission = "list"
)

// Resource defines a resource type that can be protected.
type Resource string

const (
	ResourceAgent         Resource = "agent"
	ResourceIssue         Resource = "issue"
	ResourceEvent         Resource = "event"
	ResourceNetworkPolicy Resource = "network_policy"
)

// Role represents a set of permissions that can be assigned to members.
type Role struct {
	ID          string       `json:"id"`
	ProjectID   string       `json:"project_id"`
	Name        string       `json:"name"`
	Description *string      `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
	Predefined  bool         `json:"predefined"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// CreateRole represents the request to create a new role.
type CreateRole struct {
	Name        string       `json:"name"`
	Description *string      `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
	Predefined  bool         `json:"-"` // Not settable via API
}

// RoleCreated represents the response after a role is created.
type RoleCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Validate validates the CreateRole input.
func (c *CreateRole) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return ErrRoleNameRequired
	}

	if len(c.Permissions) == 0 {
		return ErrInvalidPermission
	}

	return nil
}

// UpdateRole represents the request to update an existing role.
type UpdateRole struct {
	Name        *string      `json:"name,omitempty"`
	Description *string      `json:"description,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// RoleUpdated represents the response after a role is updated.
type RoleUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate validates the UpdateRole input.
func (u *UpdateRole) Validate() error {
	if u.Name == nil && u.Description == nil && len(u.Permissions) == 0 {
		return ErrMissingUpdateField
	}

	if u.Name != nil {
		*u.Name = strings.TrimSpace(*u.Name)
		if *u.Name == "" {
			return ErrRoleNameRequired
		}
	}

	return nil
}

// ListRoles represents the query parameters for listing roles.
type ListRoles struct {
	ProjectID string `json:"project_id,omitempty"`
	PageArgs
}

// Member represents a user's membership in a project with an assigned role.
type Member struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ProjectID string    `json:"project_id"`
	RoleID    string    `json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Role *Role `json:"role,omitempty"`
	User *User `json:"user,omitempty"`
}

// CreateMember represents the request to create a new member.
type CreateMember struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

// MemberCreated represents the response after a member is created.
type MemberCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Validate validates the CreateMember input.
func (c *CreateMember) Validate() error {
	if c.UserID == "" {
		return ErrUserIDRequired
	}

	if c.RoleID == "" {
		return ErrRoleIDRequired
	}

	return nil
}

// UpdateMember represents the request to update an existing member.
type UpdateMember struct {
	RoleID string `json:"role_id"`
}

// MemberUpdated represents the response after a member is updated.
type MemberUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate validates the UpdateMember input.
func (u *UpdateMember) Validate() error {
	if u.RoleID == "" {
		return ErrRoleIDRequired
	}

	return nil
}

// ListMembers represents the query parameters for listing members.
type ListMembers struct {
	ProjectID string `json:"project_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	RoleID    string `json:"role_id,omitempty"`
	PageArgs
}

// PredefinedRoles returns the predefined roles for a project.
func PredefinedRoles(_ string) struct {
	Admin  CreateRole
	Writer CreateRole
	Reader CreateRole
} {
	adminDesc := "Admin has all permissions"
	writerDesc := "Writer can create, read and update but not delete"
	readerDesc := "Reader can only read"

	return struct {
		Admin  CreateRole
		Writer CreateRole
		Reader CreateRole
	}{
		Admin: CreateRole{
			Name:        "Admin",
			Description: &adminDesc,
			Permissions: []Permission{PermCreate, PermRead, PermUpdate, PermDelete, PermList},
			Predefined:  true,
		},
		Writer: CreateRole{
			Name:        "Writer",
			Description: &writerDesc,
			Permissions: []Permission{PermCreate, PermRead, PermUpdate, PermList},
			Predefined:  true,
		},
		Reader: CreateRole{
			Name:        "Reader",
			Description: &readerDesc,
			Permissions: []Permission{PermRead, PermList},
			Predefined:  true,
		},
	}
}

// AllPermissions returns all available permissions.
func AllPermissions() []Permission {
	return []Permission{PermCreate, PermRead, PermUpdate, PermDelete, PermList}
}

// Has checks if a slice of permissions contains a specific permission.
func Has(permissions []Permission, perm Permission) bool {
	for _, p := range permissions {
		if p == perm {
			return true
		}
	}
	return false
}
