package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhookNotificationFiltering tests that webhook notifications are only sent
// for issue classes configured in the project settings.
//
//nolint:maintidx // This test has higher complexity due to testing multiple webhook scenarios
func TestWebhookNotificationFiltering(t *testing.T) {
	ctx := t.Context()

	// Create counters to track webhook hits
	var (
		mu          sync.Mutex
		webhookHits int
	)

	// waitForWebhookHits waits until the webhook hits counter reaches the expected value
	// or times out if the expected count is not reached within the timeout period
	waitForWebhookHits := func(expectedHits int, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		checkInterval := 50 * time.Millisecond

		for time.Now().Before(deadline) {
			mu.Lock()
			currentHits := webhookHits
			mu.Unlock()

			if currentHits >= expectedHits {
				return true
			}
			time.Sleep(checkInterval)
		}
		return false
	}

	// Create a mock webhook server to receive notifications
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		webhookHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	t.Run("default_behavior_network_exfiltration_enabled", func(t *testing.T) {
		// Use a unique client/project for this test
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a webhook
		webhook, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "test-all-classes",
			URL:  mockServer.URL,
			Kind: types.WebhookKindSlack,
		})
		require.NoError(t, err)
		require.NotEmpty(t, webhook.ID)

		// Reset counter
		mu.Lock()
		webhookHits = 0
		mu.Unlock()

		// Create an agent
		agentCreated, _ := setupAgent(ctx, t, client)
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Create events that trigger issues of different classes
		// First, a network exfiltration issue
		networkEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP, // Triggers network_exfiltration issue
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test network exfiltration event",
					Importance:  "critical",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr("203.0.113.1"),
					},
				},
			},
		}

		// Ingest the network event
		_, err = agentClient.IngestEvent(ctx, networkEvent)
		require.NoError(t, err)

		// Wait for the webhook to be triggered for the network event
		networkHitReached := waitForWebhookHits(1, 2*time.Second)
		assert.True(t, networkHitReached, "Network exfiltration event should trigger webhook")

		// Record the current number of hits
		mu.Lock()
		hitsAfterNetwork := webhookHits
		mu.Unlock()

		// Then, a crypto miner issue
		cryptoEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindCryptoMinerExecution, // Triggers crypto_miner issue
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test crypto miner event",
					Importance:  "critical",
				},
			},
		}

		// Ingest the crypto miner event
		_, err = agentClient.IngestEvent(ctx, cryptoEvent)
		require.NoError(t, err)

		// Give it some time to ensure no webhook is triggered for crypto_miner
		time.Sleep(500 * time.Millisecond)

		// Get the final webhook hit count - should still be the same as after network event
		mu.Lock()
		finalHits := webhookHits
		mu.Unlock()

		// Verify we got exactly 1 hit (only for network_exfiltration by default)
		assert.Equal(t, hitsAfterNetwork, finalHits, "Only network_exfiltration events should trigger webhook by default")

		// Clean up
		err = client.DeleteWebhook(ctx, webhook.ID)
		require.NoError(t, err)
	})

	t.Run("filtered_classes", func(t *testing.T) {
		// Use a unique client/project for this test
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a webhook
		webhook, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "test-filtered-classes",
			URL:  mockServer.URL,
			Kind: types.WebhookKindSlack,
		})
		require.NoError(t, err)
		require.NotEmpty(t, webhook.ID)

		// Set project setting to only enable network_exfiltration class
		classes := types.WebhookEnabledIssueClasses{
			Classes: []types.IssueClass{types.IssueClassNetworkExfiltration},
		}
		classesJSON, err := json.Marshal(classes)
		require.NoError(t, err)

		// Try to get existing setting first
		_, settingErr := client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		if settingErr == nil {
			// Setting exists, update it
			update := types.ProjectSettingUpdate{
				Value: json.RawMessage(classesJSON),
			}
			_, err = client.UpdateProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), update)
			require.NoError(t, err)
		} else {
			// Setting doesn't exist, create it
			create := types.ProjectSettingCreate{
				Key:   types.ProjectSettingKeyWebhookEnabledIssueClasses.String(),
				Value: json.RawMessage(classesJSON),
			}
			_, err = client.CreateProjectSetting(ctx, create)
			require.NoError(t, err)
		}

		// Reset counter
		mu.Lock()
		webhookHits = 0
		mu.Unlock()

		// Create an agent
		agentCreated, _ := setupAgent(ctx, t, client)
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// First, ingest a crypto miner event (this should NOT trigger a webhook)
		cryptoEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindCryptoMinerExecution, // Triggers crypto_miner issue
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test crypto miner event (filtered)",
					Importance:  "critical",
				},
			},
		}

		// Ingest the crypto miner event
		_, err = agentClient.IngestEvent(ctx, cryptoEvent)
		require.NoError(t, err)

		// Give it some time to ensure no webhook is triggered
		time.Sleep(500 * time.Millisecond)

		// Verify no webhook was triggered for crypto miner event
		mu.Lock()
		cryptoHits := webhookHits
		mu.Unlock()
		assert.Equal(t, 0, cryptoHits, "Crypto miner event should not trigger webhook when filtered out")

		// Then ingest a network exfiltration event (this SHOULD trigger a webhook)
		networkEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP, // Triggers network_exfiltration issue
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test network exfiltration event (filtered)",
					Importance:  "critical",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr("203.0.113.2"),
					},
				},
			},
		}

		// Ingest the network event
		_, err = agentClient.IngestEvent(ctx, networkEvent)
		require.NoError(t, err)

		// Wait for webhook to be triggered for the network event
		networkHitReached := waitForWebhookHits(1, 2*time.Second)
		assert.True(t, networkHitReached, "Network exfiltration event should trigger webhook when enabled")

		// Get the final webhook hit count
		mu.Lock()
		finalHits := webhookHits
		mu.Unlock()

		// Verify we got exactly 1 hit (only from the network event)
		assert.Equal(t, 1, finalHits, "Should have received exactly 1 webhook hit")

		// Clean up
		err = client.DeleteProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)
		err = client.DeleteWebhook(ctx, webhook.ID)
		require.NoError(t, err)
	})

	t.Run("empty_classes_disables_all", func(t *testing.T) {
		// Use a unique client/project for this test
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a webhook
		webhook, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "test-empty-classes",
			URL:  mockServer.URL,
			Kind: types.WebhookKindSlack,
		})
		require.NoError(t, err)
		require.NotEmpty(t, webhook.ID)

		// Set project setting with empty classes array (disables all notifications)
		classes := types.WebhookEnabledIssueClasses{
			Classes: []types.IssueClass{}, // Empty array
		}
		classesJSON, err := json.Marshal(classes)
		require.NoError(t, err)

		// Try to get existing setting first
		_, settingErr := client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		if settingErr == nil {
			// Setting exists, update it
			update := types.ProjectSettingUpdate{
				Value: json.RawMessage(classesJSON),
			}
			_, err = client.UpdateProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), update)
			require.NoError(t, err)
		} else {
			// Setting doesn't exist, create it
			create := types.ProjectSettingCreate{
				Key:   types.ProjectSettingKeyWebhookEnabledIssueClasses.String(),
				Value: json.RawMessage(classesJSON),
			}
			_, err = client.CreateProjectSetting(ctx, create)
			require.NoError(t, err)
		}

		// Reset counter
		mu.Lock()
		webhookHits = 0
		mu.Unlock()

		// Create an agent
		agentCreated, _ := setupAgent(ctx, t, client)
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Create events for both classes
		networkEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test network event with empty filters",
					Importance:  "critical",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr("203.0.113.5"),
					},
				},
			},
		}

		cryptoEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindCryptoMinerExecution,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test crypto event with empty filters",
					Importance:  "critical",
				},
			},
		}

		// Ingest both events
		_, err = agentClient.IngestEvent(ctx, networkEvent)
		require.NoError(t, err)
		_, err = agentClient.IngestEvent(ctx, cryptoEvent)
		require.NoError(t, err)

		// Give it some time to ensure no webhooks are triggered
		time.Sleep(1 * time.Second)

		// No events should trigger webhook hits
		mu.Lock()
		finalHits := webhookHits
		mu.Unlock()
		assert.Equal(t, 0, finalHits, "No events should trigger webhook with empty classes list")

		// Clean up
		err = client.DeleteProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)
		err = client.DeleteWebhook(ctx, webhook.ID)
		require.NoError(t, err)
	})

	t.Run("updating_classes", func(t *testing.T) {
		// Use a unique client/project for this test
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a webhook
		webhook, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "test-updating-classes",
			URL:  mockServer.URL,
			Kind: types.WebhookKindSlack,
		})
		require.NoError(t, err)
		require.NotEmpty(t, webhook.ID)

		// Initially set project setting to only enable crypto_miner class
		initialClasses := types.WebhookEnabledIssueClasses{
			Classes: []types.IssueClass{types.IssueClassCryptoMiner},
		}
		initialClassesJSON, err := json.Marshal(initialClasses)
		require.NoError(t, err)

		// Try to get existing setting first
		_, settingErr := client.ProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		if settingErr == nil {
			// Setting exists, update it
			update := types.ProjectSettingUpdate{
				Value: json.RawMessage(initialClassesJSON),
			}
			_, err = client.UpdateProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), update)
			require.NoError(t, err)
		} else {
			// Setting doesn't exist, create it
			create := types.ProjectSettingCreate{
				Key:   types.ProjectSettingKeyWebhookEnabledIssueClasses.String(),
				Value: json.RawMessage(initialClassesJSON),
			}
			_, err = client.CreateProjectSetting(ctx, create)
			require.NoError(t, err)
		}

		// Reset counter
		mu.Lock()
		webhookHits = 0
		mu.Unlock()

		// Create an agent
		agentCreated, _ := setupAgent(ctx, t, client)
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Create network event (should NOT trigger webhook)
		networkEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test network event before update",
					Importance:  "critical",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr("203.0.113.3"),
					},
				},
			},
		}

		// Create crypto event (SHOULD trigger webhook)
		cryptoEvent := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindCryptoMinerExecution,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test crypto event before update",
					Importance:  "critical",
				},
			},
		}

		// Ingest network event first (should not trigger webhook)
		_, err = agentClient.IngestEvent(ctx, networkEvent)
		require.NoError(t, err)

		// Wait a bit to make sure no webhook is triggered
		time.Sleep(500 * time.Millisecond)

		// Check that no webhook was triggered
		mu.Lock()
		hitsAfterNetwork := webhookHits
		mu.Unlock()
		assert.Equal(t, 0, hitsAfterNetwork, "Network event should not trigger webhook when only crypto_miner is enabled")

		// Ingest crypto event (should trigger webhook)
		_, err = agentClient.IngestEvent(ctx, cryptoEvent)
		require.NoError(t, err)

		// Wait for webhook to be triggered for the crypto event
		cryptoHitReached := waitForWebhookHits(1, 2*time.Second)
		assert.True(t, cryptoHitReached, "Crypto miner event should trigger webhook when crypto_miner is enabled")

		// Now update the setting to include both classes
		updatedClasses := types.WebhookEnabledIssueClasses{
			Classes: []types.IssueClass{
				types.IssueClassCryptoMiner,
				types.IssueClassNetworkExfiltration,
			},
		}
		updatedClassesJSON, err := json.Marshal(updatedClasses)
		require.NoError(t, err)

		update := types.ProjectSettingUpdate{
			Value: json.RawMessage(updatedClassesJSON),
		}

		_, err = client.UpdateProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String(), update)
		require.NoError(t, err)

		// Ensure we start from a clean state for counting the next webhooks
		mu.Lock()
		webhookHits = 0
		mu.Unlock()

		// Create new network event (should NOW trigger webhook after update)
		networkEvent2 := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test network event after update",
					Importance:  "critical",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr("203.0.113.4"),
					},
				},
			},
		}

		// Create new crypto event (should still trigger webhook)
		cryptoEvent2 := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKindCryptoMinerExecution,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test crypto event after update",
					Importance:  "critical",
				},
			},
		}

		// Ingest both events
		_, err = agentClient.IngestEvent(ctx, networkEvent2)
		require.NoError(t, err)
		_, err = agentClient.IngestEvent(ctx, cryptoEvent2)
		require.NoError(t, err)

		// Wait for both webhooks to be triggered (2 hits total)
		bothHitsReached := waitForWebhookHits(2, 2*time.Second)
		assert.True(t, bothHitsReached, "Both events should trigger webhooks after updating to include both classes")

		// Get final hit count
		mu.Lock()
		finalHits := webhookHits
		mu.Unlock()
		assert.Equal(t, 2, finalHits, "Should have exactly 2 webhook hits after both events")

		// Clean up
		err = client.DeleteProjectSetting(ctx, types.ProjectSettingKeyWebhookEnabledIssueClasses.String())
		require.NoError(t, err)
		err = client.DeleteWebhook(ctx, webhook.ID)
		require.NoError(t, err)
	})
}
