package types

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLabels(t *testing.T) {
	tests := []struct {
		name    string
		labels  map[string]string
		wantErr bool
		errType error
	}{
		{
			name: "valid labels",
			labels: map[string]string{
				"simple":          "value",
				"with-dash":       "value-with-dash",
				"with_underscore": "value_with_underscore",
				"alphanumeric123": "value123",
				"a":               "b", // Single char
			},
			wantErr: false,
		},
		{
			name:    "empty labels",
			labels:  map[string]string{},
			wantErr: false,
		},
		{
			name: "too many labels",
			labels: func() map[string]string {
				// Create a map with more labels than allowed
				m := make(map[string]string)
				for i := 0; i < MaxLabelsCount+1; i++ { //nolint:intrange
					// Use simple numbered keys: "label1", "label2", etc.
					m[fmt.Sprintf("label%d", i)] = "value"
				}
				return m
			}(),
			wantErr: true,
			errType: ErrTooManyLabels,
		},
		{
			name: "key too long",
			labels: map[string]string{
				strings.Repeat("a", MaxLabelKeyLength+1): "value",
			},
			wantErr: true,
			errType: ErrLabelKeyTooLong,
		},
		{
			name: "value too long",
			labels: map[string]string{
				"key": strings.Repeat("a", MaxLabelValueLength+1),
			},
			wantErr: true,
			errType: ErrLabelValueTooLong,
		},
		{
			name: "invalid key format - starts with dash",
			labels: map[string]string{
				"-invalid": "value",
			},
			wantErr: true,
			errType: ErrInvalidLabelKey,
		},
		{
			name: "invalid key format - ends with dash",
			labels: map[string]string{
				"invalid-": "value",
			},
			wantErr: true,
			errType: ErrInvalidLabelKey,
		},
		{
			name: "invalid key format - contains space",
			labels: map[string]string{
				"invalid key": "value",
			},
			wantErr: true,
			errType: ErrInvalidLabelKey,
		},
		{
			name: "invalid key format - contains special chars",
			labels: map[string]string{
				"invalid@key": "value",
			},
			wantErr: true,
			errType: ErrInvalidLabelKey,
		},
		{
			name: "invalid key format - sql injection attempt",
			labels: map[string]string{
				"key'; DROP TABLE labels; --": "value",
			},
			wantErr: true,
			errType: ErrInvalidLabelKey,
		},
		{
			name: "invalid value format",
			labels: map[string]string{
				"key": "value@with$special#chars",
			},
			wantErr: true,
			errType: ErrInvalidLabelValue,
		},
		{
			name: "invalid value format - sql injection attempt",
			labels: map[string]string{
				"key": "value'; DROP TABLE labels; --",
			},
			wantErr: true,
			errType: ErrInvalidLabelValue,
		},
		{
			name: "key at max length",
			labels: map[string]string{
				strings.Repeat("a", MaxLabelKeyLength): "value",
			},
			wantErr: false,
		},
		{
			name: "value at max length",
			labels: map[string]string{
				"key": strings.Repeat("a", MaxLabelValueLength),
			},
			wantErr: false,
		},
		{
			name: "valid complex labels",
			labels: map[string]string{
				"app":         "api",
				"environment": "production",
				"version":     "1.2.3",
				"tier":        "frontend",
				"region":      "us-west-2",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLabels(tt.labels)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.Equal(t, tt.errType, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAgentLabelsValidate(t *testing.T) {
	t.Run("valid agent labels", func(t *testing.T) {
		labels := AgentLabels{
			"app": "agent",
			"env": "test",
		}
		err := labels.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid agent labels", func(t *testing.T) {
		labels := AgentLabels{
			"invalid-label-": "value",
		}
		err := labels.Validate()
		require.Error(t, err)
		assert.Equal(t, ErrInvalidLabelKey, err)
	})
}

func TestIssueLabelsValidate(t *testing.T) {
	t.Run("valid issue labels", func(t *testing.T) {
		labels := IssueLabels{
			"severity": "high",
			"type":     "security",
		}
		err := labels.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid issue labels", func(t *testing.T) {
		labels := IssueLabels{
			"invalid@char": "value",
		}
		err := labels.Validate()
		require.Error(t, err)
		assert.Equal(t, ErrInvalidLabelKey, err)
	})
}

func TestRegexPatterns(t *testing.T) {
	t.Run("valid label keys", func(t *testing.T) {
		validKeys := []string{
			"a", "z", "0", "9",
			"simple", "app", "name",
			"with-dash", "multi-part-key",
			"with_underscore", "app_name",
			"alphanumeric123", "env2", "v1",
			"test-env-123", "app_v1_beta",
		}

		for _, key := range validKeys {
			assert.True(t, ValidLabelKeyRegex.MatchString(key), "Key should be valid: %s", key)
		}
	})

	t.Run("invalid label keys", func(t *testing.T) {
		invalidKeys := []string{
			"", " ", "  ",
			"-leading-dash", "trailing-dash-",
			"_leading_underscore", "trailing_underscore_",
			"special@char", "contains space", "has.dot",
			"$dollar", "with#hash",
			"sql'injection", "backslash\\",
			"has;semicolon", "quote\"mark",
		}

		for _, key := range invalidKeys {
			assert.False(t, ValidLabelKeyRegex.MatchString(key), "Key should be invalid: %s", key)
		}
	})

	t.Run("valid label values", func(t *testing.T) {
		validValues := []string{
			"a", "simple", "with-dash",
			"with_underscore", "alphanumeric123",
			"with.dot", "with/slash",
			"with space", "multi part value",
		}

		for _, value := range validValues {
			assert.True(t, ValidLabelValueRegex.MatchString(value), "Value should be valid: %s", value)
		}
	})

	t.Run("invalid label values", func(t *testing.T) {
		invalidValues := []string{
			"", " ", "  ",
			"special@char", "has#hash", "$dollar",
			"backslash\\", "has;semicolon", "quote\"mark",
			"sql'injection",
		}

		for _, value := range invalidValues {
			assert.False(t, ValidLabelValueRegex.MatchString(value), "Value should be invalid: %s", value)
		}
	})
}
