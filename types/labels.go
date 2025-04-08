package types

import (
	"regexp"

	"github.com/listendev/jibril-api/types/errs"
)

// Label constraints.
const (
	MaxLabelKeyLength   = 63   // Maximum length for label keys
	MaxLabelValueLength = 1024 // Maximum length for label values
	MaxLabelsCount      = 64   // Maximum number of labels allowed
)

// Label error constants.
var (
	ErrTooManyLabels     = errs.InvalidArgumentError("too many labels")
	ErrLabelKeyTooLong   = errs.InvalidArgumentError("label key exceeds maximum length")
	ErrLabelValueTooLong = errs.InvalidArgumentError("label value exceeds maximum length")
	ErrInvalidLabelKey   = errs.InvalidArgumentError("invalid label key format")
	ErrInvalidLabelValue = errs.InvalidArgumentError("invalid label value format")
)

// Validation regexes.
var (
	// ValidLabelKeyRegex matches alphanumeric characters, '-', '_', must start/end with alphanumeric.
	// Requirements:
	// - Must start and end with alphanumeric characters.
	// - Can contain hyphens and underscores in the middle.
	// - Single character alphanumeric keys are allowed.
	ValidLabelKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9][-_a-zA-Z0-9]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)

	// ValidLabelValueRegex allows more characters but still has controlled format.
	// Allows alphanumeric chars, hyphens, underscores, periods, forward slashes, spaces.
	ValidLabelValueRegex = regexp.MustCompile(`^[a-zA-Z0-9][-_a-zA-Z0-9/. ]*$`)
)

// ValidateLabels validates a map of labels against the defined constraints.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > MaxLabelsCount {
		return ErrTooManyLabels
	}

	for k, v := range labels {
		// Validate key
		if len(k) > MaxLabelKeyLength {
			return ErrLabelKeyTooLong
		}
		if !ValidLabelKeyRegex.MatchString(k) {
			return ErrInvalidLabelKey
		}

		// Validate value
		if len(v) > MaxLabelValueLength {
			return ErrLabelValueTooLong
		}
		if !ValidLabelValueRegex.MatchString(v) {
			return ErrInvalidLabelValue
		}
	}

	return nil
}
