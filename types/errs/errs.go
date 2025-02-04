// Package errs contains the error types returned by the jibril-server.
package errs

const InvalidArgument = InvalidArgumentError("invalid argument")

type InvalidArgumentError string

func (e InvalidArgumentError) Error() string        { return string(e) }
func (e InvalidArgumentError) Is(target error) bool { return target == InvalidArgument }

const NotFound = NotFoundError("not found")

type NotFoundError string

func (e NotFoundError) Error() string        { return string(e) }
func (e NotFoundError) Is(target error) bool { return target == NotFound }

const Unauthorized = UnauthorizedError("unauthorized")

type UnauthorizedError string

func (e UnauthorizedError) Error() string        { return string(e) }
func (e UnauthorizedError) Is(target error) bool { return target == Unauthorized }
