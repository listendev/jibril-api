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
	withToken := testclient.WithToken(t)

	t.Run("ok", func(t *testing.T) {
		event := types.Event{
			ID:      uuid.New().String(),
			AgentID: uuid.New().String(),
			Kind:    types.EventKindDropDomain,
			Data: types.EventData{
				Process: &types.Process{
					Cmd: ptr("test-cmd"),
					PID: ptr(1234),
				},
			},
		}

		{
			got, err := withToken.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		}

		// update event with same ID
		event.Data.Process.Cmd = ptr("updated-cmd")

		{
			got, err := withToken.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		}
	})

	t.Run("invalid event kind", func(t *testing.T) {
		event := types.Event{
			ID:      uuid.New().String(),
			AgentID: uuid.New().String(),
			Kind:    types.EventKind("invalid"),
		}

		_, err := withToken.IngestEvent(ctx, event)
		assert.Error(t, err)
	})
}

// setupEventWithKind creates a test event with the specified kind and returns its ID.
func setupEventWithKind(ctx context.Context, t *testing.T, client *client.Client, agentID string, kind types.EventKind) string {
	t.Helper()

	event := types.Event{
		ID:      uuid.New().String(),
		AgentID: agentID,
		Kind:    kind,
		Data: types.EventData{
			Head: &types.EventHead{
				Name:        string(kind),
				Description: "Event description for " + string(kind),
				Importance:  "critical",
			},
		},
	}

	got, err := client.IngestEvent(ctx, event)
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
				agentID, _ := setupAgent(ctx, t, client)

				// Setup event with the specified kind
				eventID := setupEventWithKind(ctx, t, client, agentID, eventKind)

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
				agentID, _ := setupAgent(ctx, t, client)

				// Setup event with the specified kind
				setupEventWithKind(ctx, t, client, agentID, eventKind)

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)

			ctx := t.Context()
			withToken := testclient.WithToken(t)

			var event types.Event

			require.NoError(t, json.Unmarshal(data, &event))

			got, err := withToken.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		})
	}
}
