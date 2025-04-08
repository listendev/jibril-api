// Package errs contains the error types returned by the jibril-server.
package errs

const (
	ErrInvalidArgument = InvalidArgumentError("invalid argument")
	ErrInternalServer  = InternalServerError("internal server error")
)

type InvalidArgumentError string

func (e InvalidArgumentError) Error() string { return string(e) }
func (e InvalidArgumentError) Is(target error) bool {
	if target == ErrInvalidArgument {
		return true // All InvalidArgumentError types should match ErrInvalidArgument
	}
	if target, ok := target.(InvalidArgumentError); ok {
		return e == target
	}
	return false
}

type InternalServerError string

func (e InternalServerError) Error() string { return string(e) }
func (e InternalServerError) Is(target error) bool {
	if target == ErrInternalServer {
		return true // All InternalServerError types should match ErrInternalServer
	}
	if target, ok := target.(InternalServerError); ok {
		return e == target
	}
	return false
}

const ErrNotFound = NotFoundError("not found")

type NotFoundError string

func (e NotFoundError) Error() string { return string(e) }
func (e NotFoundError) Is(target error) bool {
	if target, ok := target.(NotFoundError); ok {
		return e == target
	}
	return false
}

const ErrUnauthorized = UnauthorizedError("unauthorized")

type UnauthorizedError string

func (e UnauthorizedError) Error() string { return string(e) }
func (e UnauthorizedError) Is(target error) bool {
	if target == ErrUnauthorized {
		return true // All UnauthorizedError types should match ErrUnauthorized
	}
	if target, ok := target.(UnauthorizedError); ok {
		return e == target
	}
	return false
}

const ErrInvalidAgentID = InvalidAgentIDError("invalid agent ID")

type InvalidAgentIDError string

func (e InvalidAgentIDError) Error() string { return string(e) }
func (e InvalidAgentIDError) Is(target error) bool {
	if target, ok := target.(InvalidAgentIDError); ok {
		return e == target
	}
	return false
}

const ErrConflict = ConflictError("resource already exists")

type ConflictError string

func (e ConflictError) Error() string { return string(e) }
func (e ConflictError) Is(target error) bool {
	if target == ErrConflict {
		return true // All ConflictError types should match ErrConflict
	}
	if target, ok := target.(ConflictError); ok {
		return e == target
	}
	return false
}

const ErrPermissionDenied = PermissionDeniedError("permission denied")

type PermissionDeniedError string

func (e PermissionDeniedError) Error() string { return string(e) }
func (e PermissionDeniedError) Is(target error) bool {
	if target == ErrPermissionDenied {
		return true // All PermissionDeniedError types should match ErrPermissionDenied
	}
	if target, ok := target.(PermissionDeniedError); ok {
		return e == target
	}
	return false
}
