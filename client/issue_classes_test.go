package client_test

import (
	"testing"

	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueClasses(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("fetch_all_issue_classes", func(t *testing.T) {
		classes, err := client.IssueClasses(ctx)
		require.NoError(t, err)

		// Verify we get expected built-in issue classes
		assert.NotEmpty(t, classes, "Should return at least one issue class")

		// Verify specific classes are included
		foundNetworkExfiltration := false
		foundCryptoMiner := false

		for _, class := range classes {
			if class == types.IssueClassNetworkExfiltration {
				foundNetworkExfiltration = true
			}
			if class == types.IssueClassCryptoMiner {
				foundCryptoMiner = true
			}
		}

		assert.True(t, foundNetworkExfiltration, "Should include network_exfiltration class")
		assert.True(t, foundCryptoMiner, "Should include crypto_miner class")
	})

	t.Run("verify_all_classes_are_valid", func(t *testing.T) {
		classes, err := client.IssueClasses(ctx)
		require.NoError(t, err)

		// Verify all returned classes are valid according to types.IssueClass.IsValid()
		for _, class := range classes {
			assert.True(t, class.IsValid(), "All returned classes should be valid")
		}
	})

	t.Run("verify_matches_allenabledissueclasses", func(t *testing.T) {
		classes, err := client.IssueClasses(ctx)
		require.NoError(t, err)

		// Check that the endpoint returns the same classes as the AllEnabledIssueClasses helper
		expectedClasses := types.AllEnabledIssueClasses()
		assert.Equal(t, len(expectedClasses), len(classes), "Should return same number of classes as AllEnabledIssueClasses")

		// Sort both slices to ensure order-independent comparison (if needed)
		// sort.Slice(classes, func(i, j int) bool { return string(classes[i]) < string(classes[j]) })
		// sort.Slice(expectedClasses, func(i, j int) bool { return string(expectedClasses[i]) < string(expectedClasses[j]) })

		// Check each expected class is in the returned set
		for _, expected := range expectedClasses {
			found := false
			for _, actual := range classes {
				if expected == actual {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected class %s not found in API response", expected)
		}
	})

	t.Run("with_project_token", func(t *testing.T) {
		// Test that the endpoint also works with project token
		_, projectClient := testclient.WithProjectTokenForTest(t)
		classes, err := projectClient.IssueClasses(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, classes, "Should work with project token")
	})
}
