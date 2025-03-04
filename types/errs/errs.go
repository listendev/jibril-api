// Package errs contains the error types returned by the jibril-server.
package errs

const ErrInvalidArgument = InvalidArgumentError("invalid argument")

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
