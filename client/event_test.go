package client_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
	"github.com/stretchr/testify/assert"
)

// Note: The ingestEvent function was removed since it's unused

func TestIngestEvent(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// First create an agent to get a token
	agentCreated, _ := setupAgent(ctx, t, client)

	// Create a client with the agent token
	agentClient := client.WithAgentToken(agentCreated.AgentToken)

	t.Run("ok", func(t *testing.T) {
		event := types.Event{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID, // Use the created agent ID
			Kind:    types.EventKindDropDomain,
			Data: types.EventData{
				Process: &types.Process{
					Cmd: ptr("test-cmd"),
					PID: ptr(1234),
				},
			},
		}

		{
			got, err := agentClient.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		}

		// update event with same ID
		event.Data.Process.Cmd = ptr("updated-cmd")

		{
			got, err := agentClient.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		}
	})

	t.Run("invalid event kind", func(t *testing.T) {
		event := types.Event{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKind("invalid"),
		}

		_, err := agentClient.IngestEvent(ctx, event)
		assert.Error(t, err)
	})

	t.Run("mismatched agent id is denied", func(t *testing.T) {
		// Create a second agent
		secondAgentCreated, _ := setupAgent(ctx, t, client)

		// Use the token from the first agent but try to submit an event with the second agent's ID
		event := types.Event{
			ID:      uuid.New().String(),
			AgentID: secondAgentCreated.ID, // Use the second agent's ID
			Kind:    types.EventKindDropDomain,
			Data: types.EventData{
				Process: &types.Process{
					Cmd: ptr("test-cmd"),
					PID: ptr(1234),
				},
			},
		}

		// Use the first agent's token for authorization
		_, err := agentClient.IngestEvent(ctx, event)

		// Verify the API correctly returns an unauthorized error
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized")
	})

	t.Run("missing agent id uses token agent id", func(t *testing.T) {
		// Submit an event with no agent ID specified
		event := types.Event{
			ID:   uuid.New().String(),
			Kind: types.EventKindFlow, // Using Flow since it triggers issue creation
			Data: types.EventData{
				Head: &types.EventHead{
					Name:        string(types.EventKindFlow),
					Description: "Flow event for agent ID test",
					Importance:  "critical",
				},
			},
		}

		// Verify the event is accepted
		got, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.NotZero(t, got.ID)

		// Wait for issue creation and verify the event was stored with the correct agent ID
		// Check that an issue was created
		issues, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)
		require.NotEmpty(t, issues.Items, "No issues created for flow event")

		// Find our issue
		var foundIssue bool
		for _, issue := range issues.Items {
			// Look for our event in the issue's events
			for _, e := range issue.Events {
				if e.ID == event.ID {
					// Verify the event was stored with the agent ID from the token
					assert.Equal(t, agentCreated.ID, e.AgentID, "Event should have agent ID from token")
					foundIssue = true
					break
				}
			}
			if foundIssue {
				break
			}
		}

		require.True(t, foundIssue, "Could not find our event in any issue")
	})
}

// setupEventWithKind creates a test event with the specified kind and returns its ID.
func setupEventWithKind(ctx context.Context, t *testing.T, client *client.Client, agentCreated types.AgentCreated, kind types.EventKind) string {
	t.Helper()

	// Create a client with the agent token
	agentClient := client.WithAgentToken(agentCreated.AgentToken)

	event := types.Event{
		ID:      uuid.New().String(),
		AgentID: agentCreated.ID,
		Kind:    kind,
		Data: types.EventData{
			Head: &types.EventHead{
				Name:        string(kind),
				Description: "Event description for " + string(kind),
				Importance:  "critical",
			},
		},
	}

	got, err := agentClient.IngestEvent(ctx, event)
	require.NoError(t, err, "Failed to ingest event")
	require.NotZero(t, got.ID, "Expected event ID to be returned")

	return event.ID
}

// TestEventProcessorIssueCreation verifies that the event processor creates issues for specific security events.
func TestEventProcessorIssueCreation(t *testing.T) {
	ctx := t.Context()

	t.Run("security_events_create_issues", func(t *testing.T) {
		// Map of event kinds to their expected issue class
		securityEvents := map[types.EventKind]types.IssueClass{
			types.EventKindDropIP:               types.IssueClassNetworkExfiltration,
			types.EventKindDropDomain:           types.IssueClassNetworkExfiltration,
			types.EventKindFlow:                 types.IssueClassNetworkExfiltration,
			types.EventKindCryptoMinerExecution: types.IssueClassCryptoMiner,
			types.EventKindCryptoMinerFiles:     types.IssueClassCryptoMiner,
		}

		for eventKind, expectedClass := range securityEvents {
			t.Run(string(eventKind), func(t *testing.T) {
				// Use a unique client/project for this test to isolate issues
				client := testclient.WithToken(t)

				// First create a valid agent for this project
				agentCreated, _ := setupAgent(ctx, t, client)

				// Setup event with the specified kind
				eventID := setupEventWithKind(ctx, t, client, agentCreated, eventKind)

				// Check that an issue was created
				issues, err := client.Issues(ctx, types.ListIssues{})
				require.NoError(t, err)
				require.NotEmpty(t, issues.Items, "No issues created for event kind %s", eventKind)
				require.Len(t, issues.Items, 1, "Expected exactly one issue for event kind %s", eventKind)

				// Verify the issue properties directly
				issue := issues.Items[0]

				// Check if the event with our ID is in the issue
				var eventFound bool
				for _, e := range issue.Events {
					if e.ID == eventID {
						eventFound = true
						break
					}
				}
				require.True(t, eventFound, "Issue should contain our event with ID %s", eventID)

				assert.Equal(t, expectedClass, issue.Class, "Issue for %s has incorrect class", eventKind)
				assert.Equal(t, types.IssuePriorityCritical, issue.Priority, "Issue for %s has incorrect priority", eventKind)
				assert.Contains(t, issue.Labels, "event_kind")
				assert.Equal(t, string(eventKind), issue.Labels["event_kind"])
			})
		}
	})

	t.Run("non_security_events_dont_create_issues", func(t *testing.T) {
		// Test event kinds that should NOT create issues
		nonSecurityEvents := []types.EventKind{
			types.EventKindAdultDomainAccess,
			types.EventKindFilesystemFingerprint,
			types.EventKindNetScanToolExec,
		}

		for _, eventKind := range nonSecurityEvents {
			t.Run(string(eventKind), func(t *testing.T) {
				// Use a unique client/project for this test to isolate issues
				client := testclient.WithToken(t)

				// First create a valid agent for this project
				agentCreated, _ := setupAgent(ctx, t, client)

				// Setup event with the specified kind
				setupEventWithKind(ctx, t, client, agentCreated, eventKind)

				// Verify no issues were created
				issues, err := client.Issues(ctx, types.ListIssues{})
				require.NoError(t, err)
				assert.Empty(t, issues.Items, "Issues were incorrectly created for event kind %s", eventKind)
			})
		}
	})
}

func TestIngestUnmarshaledEvents(t *testing.T) {
	type test struct {
		name string
		file string
	}

	tests := []test{
		{name: "adult_domain_access", file: "./testdata/adult_domain_access.json"},
		{name: "flow", file: "./testdata/flow.json"},
		{name: "drop_ip", file: "./testdata/drop_ip.json"},
		{name: "filesystem_fingerprint", file: "./testdata/filesystem_fingerprint.json"},
		{name: "exec_from_unusual_dir", file: "./testdata/exec_from_unusual_dir.json"},
		{name: "net_scan_tool_exec", file: "./testdata/net_scan_tool_exec.json"},
		{name: "sudoers_modification", file: "./testdata/sudoers_modification.json"},
		{name: "interpreter_shell_spawn", file: "./testdata/interpreter_shell_spawn.json"},
		{name: "net_suspicious_tool_exec", file: "./testdata/net_suspicious_tool_exec.json"},
		{name: "os_status_fingerprint", file: "./testdata/os_status_fingerprint.json"},
		{name: "crypto_miner_files", file: "./testdata/crypto_miner_files.json"},
	}

	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create an agent to get a token
	agentCreated, _ := setupAgent(ctx, t, client)

	// Create a client with the agent token
	agentClient := client.WithAgentToken(agentCreated.AgentToken)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)

			var event types.Event
			require.NoError(t, json.Unmarshal(data, &event))

			// Set the agent ID to match our authenticated agent
			event.AgentID = agentCreated.ID

			got, err := agentClient.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		})
	}
}
