package client_test

import (
	"encoding/json"
	"testing"

	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectSettings(t *testing.T) {
	ctx := t.Context()

	t.Run("CRUD operations", func(t *testing.T) {
		// Setup test client with project token
		_, client := testclient.WithProjectTokenForTest(t)

		// Since we now create default settings for new projects, we need to modify the test
		// First check if the setting already exists
		var existingSetting types.ProjectSetting
		var err error
		var settingID string

		existingSetting, err = client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		if err == nil {
			// Setting exists, let's remember its ID
			settingID = existingSetting.ID
		} else {
			// Setting doesn't exist, create it
			classes := types.WebhookEnabledIssueClasses{
				Classes: []types.IssueClass{
					types.IssueClassNetworkExfiltration,
					types.IssueClassCryptoMiner,
				},
			}

			// Convert to JSON
			classesJSON, err := json.Marshal(classes)
			require.NoError(t, err)

			// Create the setting
			create := types.ProjectSettingCreate{
				Key:   types.ProjectSettingKeyWebhookEnabledIssueClasses.String(),
				Value: json.RawMessage(classesJSON),
			}

			// Test Create
			created, err := client.CreateProjectSetting(ctx, create)
			require.NoError(t, err)
			assert.Equal(t, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), created.Key)
			assert.NotEmpty(t, created.ID)
			settingID = created.ID
		}

		// Test Get
		setting, err := client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)
		assert.Equal(t, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), setting.Key)
		assert.Equal(t, settingID, setting.ID)

		// Parse the value
		var retrievedClasses types.WebhookEnabledIssueClasses
		err = json.Unmarshal(setting.Value, &retrievedClasses)
		require.NoError(t, err)

		// Always update the setting to include both classes for testing
		// regardless of what's in there originally
		initialClasses := types.WebhookEnabledIssueClasses{
			Classes: []types.IssueClass{
				types.IssueClassNetworkExfiltration,
				types.IssueClassCryptoMiner,
			},
		}
		initialClassesJSON, err := json.Marshal(initialClasses)
		require.NoError(t, err)

		initialUpdate := types.ProjectSettingUpdate{
			Value: json.RawMessage(initialClassesJSON),
		}
		initialUpdated, err := client.UpdateProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), initialUpdate)
		require.NoError(t, err)
		assert.Equal(t, settingID, initialUpdated.ID)

		// Re-read it to ensure it has both classes now
		setting, err = client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)
		var retrievedUpdatedClasses types.WebhookEnabledIssueClasses
		err = json.Unmarshal(setting.Value, &retrievedUpdatedClasses)
		require.NoError(t, err)
		assert.Len(t, retrievedUpdatedClasses.Classes, 2)
		assert.Contains(t, retrievedUpdatedClasses.Classes, types.IssueClassNetworkExfiltration)
		assert.Contains(t, retrievedUpdatedClasses.Classes, types.IssueClassCryptoMiner)

		// Test Update - modify the classes
		newClasses := types.WebhookEnabledIssueClasses{
			Classes: []types.IssueClass{
				types.IssueClassNetworkExfiltration, // Keep only one class
			},
		}
		newClassesJSON, err := json.Marshal(newClasses)
		require.NoError(t, err)

		update := types.ProjectSettingUpdate{
			Value: json.RawMessage(newClassesJSON),
		}
		updated, err := client.UpdateProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), update)
		require.NoError(t, err)
		assert.Equal(t, settingID, updated.ID)

		// Test Get after update
		settingAfterUpdate, err := client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)
		var updatedClasses types.WebhookEnabledIssueClasses
		err = json.Unmarshal(settingAfterUpdate.Value, &updatedClasses)
		require.NoError(t, err)
		assert.Len(t, updatedClasses.Classes, 1)
		assert.Contains(t, updatedClasses.Classes, types.IssueClassNetworkExfiltration)
		assert.NotContains(t, updatedClasses.Classes, types.IssueClassCryptoMiner)

		// Test List
		var pageArgs types.PageArgs
		first := uint(10)
		pageArgs.First = &first

		settingsPage, err := client.ProjectSettings(ctx, &pageArgs)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(settingsPage.Items), 1)

		// Find our setting in the list
		var foundSetting bool
		for _, item := range settingsPage.Items {
			if item.ID == settingID {
				foundSetting = true
				break
			}
		}
		assert.True(t, foundSetting, "Setting should be in the list")

		// Test Delete
		err = client.DeleteProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)

		// Verify deletion
		_, err = client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.Error(t, err) // Should return an error (not found)
	})

	t.Run("validation", func(t *testing.T) {
		// Setup test client
		_, client := testclient.WithProjectTokenForTest(t)

		// Test invalid key
		invalidKey := types.ProjectSettingCreate{
			Key:   "invalid_key",
			Value: json.RawMessage(`{"foo": "bar"}`),
		}
		_, err := client.CreateProjectSetting(ctx, invalidKey)
		require.Error(t, err)

		// Test invalid value
		invalidValue := types.ProjectSettingCreate{
			Key:   types.ProjectSettingKeyWebhookEnabledIssueClasses.String(),
			Value: json.RawMessage(`{invalid json]`),
		}
		_, err = client.CreateProjectSetting(ctx, invalidValue)
		require.Error(t, err)

		// Test invalid issue class
		invalidClass := types.ProjectSettingCreate{
			Key:   types.ProjectSettingKeyWebhookEnabledIssueClasses.String(),
			Value: json.RawMessage(`{"classes": ["invalid_class"]}`),
		}
		_, err = client.CreateProjectSetting(ctx, invalidClass)
		require.Error(t, err)
	})

	t.Run("default settings", func(t *testing.T) {
		// Setup test env with a new project
		_, client := testclient.WithProjectTokenForTest(t)

		// Try to get the project setting that should be automatically created
		setting, err := client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err, "Default webhook_enabled_issue_classes setting should exist")
		assert.Equal(t, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), setting.Key)
		assert.NotEmpty(t, setting.ID)

		// Parse the value to check it has the expected default (network_exfiltration only)
		var classes types.WebhookEnabledIssueClasses
		err = json.Unmarshal(setting.Value, &classes)
		require.NoError(t, err)

		// Verify it has exactly one class: network_exfiltration
		assert.Len(t, classes.Classes, 1, "Should have exactly one enabled class by default")
		assert.Equal(t, types.IssueClassNetworkExfiltration, classes.Classes[0],
			"Default enabled class should be network_exfiltration")

		// Verify crypto_miner is not enabled
		assert.NotContains(t, classes.Classes, types.IssueClassCryptoMiner,
			"crypto_miner should not be enabled by default")
	})
}
