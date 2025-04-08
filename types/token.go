package types

import (
	"time"

	"github.com/listendev/jibril-api/types/errs"
)

// Token name constraints.
const (
	MaxTokenNameLength = 64
)

// Project token error constants.
const (
	ErrInvalidTokenName        = errs.InvalidArgumentError("invalid token name")
	ErrTokenNameTooLong        = errs.InvalidArgumentError("token name exceeds maximum length")
	ErrTokenNotFound           = errs.NotFoundError("token not found")
	ErrTokenExists             = errs.ConflictError("token already exists")
	ErrUnauthorizedTokenAccess = errs.UnauthorizedError("permission denied for token access")
)

// Token represents a project API token.
type Token struct {
	ID          string       `json:"id"`
	ProjectID   string       `json:"project_id"`
	Name        string       `json:"name"`
	Hash        string       `json:"-"` // Not exposed in API
	UserID      string       `json:"user_id"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	LastUsed    *time.Time   `json:"last_used,omitempty"`
	DeletedAt   *time.Time   `json:"deleted_at,omitempty"`
}

// CreateToken represents the request to create a new token.
type CreateToken struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	ProjectID   string       `json:"-"` // Populated by the service layer, not exposed in API
	UserID      string       `json:"-"` // Populated by the service layer, not exposed in API
	Hash        string       `json:"-"` // Hash of the JWT token, populated by the service layer
}

// Validate ensures the CreateToken request is valid.
func (c *CreateToken) Validate() error {
	if c.Name == "" {
		return ErrInvalidTokenName
	}

	if len(c.Name) > MaxTokenNameLength {
		return ErrTokenNameTooLong
	}

	// Empty permissions list means all permissions will be granted
	// Let's validate if permissions are provided
	if len(c.Permissions) > 0 {
		for _, p := range c.Permissions {
			valid := false
			for _, validPerm := range AllPermissions() {
				if p == validPerm {
					valid = true
					break
				}
			}
			if !valid {
				return ErrInvalidPermission
			}
		}
	}

	return nil
}

// TokenCreated represents the response when a token is successfully created.
type TokenCreated struct {
	ID          string       `json:"id"`
	ProjectID   string       `json:"project_id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Token       string       `json:"token"` // Actual token value, only returned once
	CreatedAt   time.Time    `json:"created_at"`
}

// UpdateToken represents the request to update an existing token.
type UpdateToken struct {
	Name        *string      `json:"name,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// Validate ensures the UpdateToken request is valid.
func (u *UpdateToken) Validate() error {
	// Check if any fields are specified
	if u.Name == nil && len(u.Permissions) == 0 {
		return errs.InvalidArgumentError("at least one field is required")
	}

	// Validate name if provided
	if u.Name != nil {
		if *u.Name == "" {
			return ErrInvalidTokenName
		}

		if len(*u.Name) > MaxTokenNameLength {
			return ErrTokenNameTooLong
		}
	}

	// Validate permissions if provided
	if len(u.Permissions) > 0 {
		for _, p := range u.Permissions {
			valid := false
			for _, validPerm := range AllPermissions() {
				if p == validPerm {
					valid = true
					break
				}
			}
			if !valid {
				return ErrInvalidPermission
			}
		}
	}

	return nil
}

// TokenUpdated represents the response when a token is successfully updated.
type TokenUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListTokens represents the request to list tokens.
type ListTokens struct {
	PageArgs  PageArgs `json:"-"` // For pagination
	ProjectID string   `json:"-"` // Populated by the service layer
}
