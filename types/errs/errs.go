// Package errs contains the error types returned by the jibril-server.
package errs

import "errors"

const ErrInvalidArgument = InvalidArgumentError("invalid argument")

type InvalidArgumentError string

func (e InvalidArgumentError) Error() string        { return string(e) }
func (e InvalidArgumentError) Is(target error) bool { return errors.Is(target, ErrInvalidArgument) }

const ErrNotFound = NotFoundError("not found")

type NotFoundError string

func (e NotFoundError) Error() string        { return string(e) }
func (e NotFoundError) Is(target error) bool { return errors.Is(target, ErrNotFound) }

const ErrUnauthorized = UnauthorizedError("unauthorized")

type UnauthorizedError string

func (e UnauthorizedError) Error() string        { return string(e) }
func (e UnauthorizedError) Is(target error) bool { return errors.Is(target, ErrUnauthorized) }
