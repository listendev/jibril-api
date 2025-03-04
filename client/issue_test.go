package client_test

import (
	"context"
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
	"github.com/stretchr/testify/assert"
)

// Helper function that compares the error message content with the expected error.
func assertErrorType(t *testing.T, err error, expectedError error) {
	t.Helper()

	// Assert that error exists
	require.Error(t, err)

	// Get the expected error message
	expectedMsg := expectedError.Error()

	// Check error message is in the response
	assert.Contains(t, err.Error(), expectedMsg)
}

// IssueOption represents a function that modifies a CreateIssue request.
type IssueOption func(*types.CreateIssue)

// WithClass sets the issue class.
func WithClass(class types.IssueClass) IssueOption {
	return func(i *types.CreateIssue) {
		i.Class = class
	}
}

// WithDescription sets the issue description.
func WithDescription(description string) IssueOption {
	return func(i *types.CreateIssue) {
		i.Description = description
	}
}

// WithIssueState sets the issue state.
func WithIssueState(state types.IssueState) IssueOption {
	return func(i *types.CreateIssue) {
		i.State = state
	}
}

// WithIssuePriority sets the issue priority.
func WithIssuePriority(priority types.IssuePriority) IssueOption {
	return func(i *types.CreateIssue) {
		i.Priority = priority
	}
}

// WithIssueLabels sets the issue labels.
func WithIssueLabels(labels types.IssueLabels) IssueOption {
	return func(i *types.CreateIssue) {
		i.Labels = labels
	}
}

// WithEventIDs sets the event IDs.
func WithEventIDs(eventIDs []string) IssueOption {
	return func(i *types.CreateIssue) {
		i.EventIDs = eventIDs
	}
}

// setupEvent creates a test event and returns its ID.
func setupEvent(ctx context.Context, t *testing.T, client *client.Client, agentID string) string {
	t.Helper()

	event := types.Event{
		ID:      uuid.New().String(),
		AgentID: agentID,
		Kind:    types.EventKindFlow,
		Data: types.EventData{
			Process: &types.Process{
				Cmd: ptr("test-cmd"),
				PID: ptr(1234),
			},
			Note: ptr("Test event"),
		},
	}

	got, err := client.IngestEvent(ctx, event)
	require.NoError(t, err, "Failed to ingest event")
	require.NotZero(t, got.ID, "Expected event ID to be returned")

	return event.ID
}

// setupIssue creates a test issue with the given options and returns the issue ID.
func setupIssue(ctx context.Context, t *testing.T, client *client.Client, eventID string, opts ...IssueOption) string {
	t.Helper()

	// Create default issue
	issue := types.CreateIssue{
		Class:       types.IssueClassNetworkExfiltration,
		Description: "Test issue description",
		State:       types.IssueStateTriaged,
		Priority:    types.IssuePriorityMedium,
		Labels: types.IssueLabels{
			"severity": "medium",
			"type":     "bug",
		},
		EventIDs: []string{eventID},
	}

	// Apply all options
	for _, opt := range opts {
		opt(&issue)
	}

	// Create the issue
	created, err := client.CreateIssue(ctx, issue)
	require.NoError(t, err, "Failed to create issue")
	require.NotEmpty(t, created.ID, "Expected issue ID to be returned")

	return created.ID
}

func TestCreateIssue(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create an agent to use for testing
	agentID, _ := setupAgent(ctx, t, client)

	// Create an event to associate with issues
	eventID := setupEvent(ctx, t, client, agentID)

	t.Run("empty payload", func(t *testing.T) {
		_, err := client.CreateIssue(ctx, types.CreateIssue{})
		require.Error(t, err)
	})

	t.Run("missing event IDs", func(t *testing.T) {
		_, err := client.CreateIssue(ctx, types.CreateIssue{
			Class:       types.IssueClassNetworkExfiltration,
			Description: "Test description",
			State:       types.IssueStateTriaged,
			Priority:    types.IssuePriorityMedium,
			Labels: types.IssueLabels{
				"severity": "medium",
			},
			// No EventIDs provided
		})
		assertErrorType(t, err, types.ErrInvalidIssueEventIDs)
	})

	t.Run("invalid state", func(t *testing.T) {
		_, err := client.CreateIssue(ctx, types.CreateIssue{
			Class:       types.IssueClassNetworkExfiltration,
			Description: "Test description",
			State:       types.IssueState("invalid-state"),
			Priority:    types.IssuePriorityMedium,
			Labels: types.IssueLabels{
				"severity": "medium",
			},
			EventIDs: []string{eventID},
		})
		assertErrorType(t, err, types.ErrInvalidIssueState)
	})

	t.Run("invalid priority", func(t *testing.T) {
		_, err := client.CreateIssue(ctx, types.CreateIssue{
			Class:       types.IssueClassNetworkExfiltration,
			Description: "Test description",
			State:       types.IssueStateTriaged,
			Priority:    types.IssuePriority("invalid-priority"),
			Labels: types.IssueLabels{
				"severity": "medium",
			},
			EventIDs: []string{eventID},
		})
		assertErrorType(t, err, types.ErrInvalidIssuePriority)
	})

	t.Run("invalid class", func(t *testing.T) {
		_, err := client.CreateIssue(ctx, types.CreateIssue{
			Class:       types.IssueClass("invalid-class"),
			Description: "Test description",
			State:       types.IssueStateTriaged,
			Priority:    types.IssuePriorityMedium,
			Labels: types.IssueLabels{
				"severity": "medium",
			},
			EventIDs: []string{eventID},
		})
		assertErrorType(t, err, types.ErrInvalidIssueClass)
	})

	t.Run("unauthorized event", func(t *testing.T) {
		_, err := client.CreateIssue(ctx, types.CreateIssue{
			Class:       types.IssueClassNetworkExfiltration,
			Description: "Test description",
			State:       types.IssueStateTriaged,
			Priority:    types.IssuePriorityMedium,
			Labels: types.IssueLabels{
				"severity": "medium",
			},
			EventIDs: []string{uuid.New().String()}, // Random UUID that doesn't exist
		})
		assertErrorType(t, err, types.ErrUnauthorizedEvents)
	})

	t.Run("ok", func(t *testing.T) {
		issueCreated, err := client.CreateIssue(ctx, types.CreateIssue{
			Class:       types.IssueClassNetworkExfiltration,
			Description: "Test issue description",
			State:       types.IssueStateTriaged,
			Priority:    types.IssuePriorityMedium,
			Labels: types.IssueLabels{
				"severity": "medium",
				"type":     "bug",
			},
			EventIDs: []string{eventID},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, issueCreated.ID)
		assert.NotZero(t, issueCreated.CreatedAt)
		assert.NotZero(t, issueCreated.UpdatedAt)
	})

	t.Run("with options", func(t *testing.T) {
		issueID := setupIssue(ctx, t, client, eventID,
			WithClass(types.IssueClassCryptoMiner),
			WithDescription("Custom description"),
			WithIssueState(types.IssueStateBlocked),
			WithIssuePriority(types.IssuePriorityHigh),
			WithIssueLabels(types.IssueLabels{
				"severity": "high",
				"area":     "security",
			}),
		)

		// Verify the issue was created with custom options
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueClassCryptoMiner, issue.Class)
		assert.Equal(t, "Custom description", issue.Description)
		assert.Equal(t, types.IssueStateBlocked, issue.State)
		assert.Equal(t, types.IssuePriorityHigh, issue.Priority)
		assert.Equal(t, "high", issue.Labels["severity"])
		assert.Equal(t, "security", issue.Labels["area"])
	})
}

func TestIssue(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentID, _ := setupAgent(ctx, t, client)
	eventID := setupEvent(ctx, t, client, agentID)
	issueID := setupIssue(ctx, t, client, eventID)

	t.Run("invalid UUID", func(t *testing.T) {
		_, err := client.Issue(ctx, "not-a-uuid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue ID")
	})

	t.Run("not found", func(t *testing.T) {
		_, err := client.Issue(ctx, uuid.New().String())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ok", func(t *testing.T) {
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, issueID, issue.ID)
		assert.Equal(t, types.IssueClassNetworkExfiltration, issue.Class)
		assert.Equal(t, "Test issue description", issue.Description)
		assert.Equal(t, types.IssueStateTriaged, issue.State)
		assert.Equal(t, types.IssuePriorityMedium, issue.Priority)
		assert.Contains(t, issue.Labels, "severity")
		assert.Equal(t, "medium", issue.Labels["severity"])
		assert.Contains(t, issue.Labels, "type")
		assert.Equal(t, "bug", issue.Labels["type"])

		// New assertions for Events
		assert.NotNil(t, issue.Events, "Events should not be nil")
		assert.Len(t, issue.Events, 1, "Should have 1 event associated with the issue")
		assert.Equal(t, eventID, issue.Events[0].ID, "Event ID should match the one used to create the issue")
		assert.Equal(t, agentID, issue.Events[0].AgentID, "Event agent ID should match")

		// Check event data if needed
		assert.NotNil(t, issue.Events[0].Data.Process, "Event process data should not be nil")
		assert.Equal(t, "test-cmd", *issue.Events[0].Data.Process.Cmd)
		assert.Equal(t, 1234, *issue.Events[0].Data.Process.PID)
		assert.Equal(t, "Test event", *issue.Events[0].Data.Note)
	})

	t.Run("multiple events", func(t *testing.T) {
		// Create a second event
		secondEventID := setupEvent(ctx, t, client, agentID)

		// Create an issue with multiple events
		multiEventIssueID := setupIssue(ctx, t, client, eventID,
			WithEventIDs([]string{eventID, secondEventID}))

		// Retrieve and verify the issue has both events
		issue, err := client.Issue(ctx, multiEventIssueID)
		require.NoError(t, err)
		assert.NotNil(t, issue.Events, "Events should not be nil")
		assert.Len(t, issue.Events, 2, "Should have 2 events associated with the issue")

		// Verify both event IDs are present (order may vary)
		eventIDs := []string{issue.Events[0].ID, issue.Events[1].ID}
		assert.Contains(t, eventIDs, eventID)
		assert.Contains(t, eventIDs, secondEventID)
	})
}

func TestUpdateIssue(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentID, _ := setupAgent(ctx, t, client)
	eventID := setupEvent(ctx, t, client, agentID)
	issueID := setupIssue(ctx, t, client, eventID)

	t.Run("invalid UUID", func(t *testing.T) {
		_, err := client.UpdateIssue(ctx, "not-a-uuid", types.UpdateIssue{
			Description: ptr("Updated description"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue ID")
	})

	t.Run("no changes", func(t *testing.T) {
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one field is required")
	})

	t.Run("invalid state", func(t *testing.T) {
		invalidState := types.IssueState("invalid-state")
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			State: &invalidState,
		})
		assertErrorType(t, err, types.ErrInvalidIssueState)
	})

	t.Run("state to ignored without ignore_for", func(t *testing.T) {
		ignoredState := types.IssueStateIgnored
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			State:  &ignoredState,
			Reason: ptr("Testing ignore"),
			// Missing IgnoreFor
		})
		assertErrorType(t, err, types.ErrInvalidIssueIgnoreFor)
	})

	t.Run("state without reason", func(t *testing.T) {
		blockedState := types.IssueStateBlocked
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			State: &blockedState,
			// Missing reason
		})
		assertErrorType(t, err, types.ErrInvalidIssueReason)
	})

	t.Run("empty class", func(t *testing.T) {
		emptyClass := types.IssueClass("")
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			Class: &emptyClass,
		})
		assertErrorType(t, err, types.ErrInvalidIssueClass)
	})

	t.Run("invalid class", func(t *testing.T) {
		invalidClass := types.IssueClass("some-invalid-class")
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			Class: &invalidClass,
		})
		assertErrorType(t, err, types.ErrInvalidIssueClass)
	})

	t.Run("empty description", func(t *testing.T) {
		emptyDesc := ""
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			Description: &emptyDesc,
		})
		assertErrorType(t, err, types.ErrInvalidIssueDescription)
	})

	t.Run("update description", func(t *testing.T) {
		newDescription := "Updated issue description"
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			Description: &newDescription,
		})
		require.NoError(t, err)
		assert.Equal(t, issueID, updated.ID)
		assert.NotZero(t, updated.UpdatedAt)

		// Verify changes were applied
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, newDescription, issue.Description)
	})

	t.Run("update priority", func(t *testing.T) {
		newPriority := types.IssuePriorityHigh
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			Priority: &newPriority,
		})
		require.NoError(t, err)
		assert.Equal(t, issueID, updated.ID)

		// Verify changes were applied
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, newPriority, issue.Priority)
	})

	t.Run("update labels", func(t *testing.T) {
		newLabels := types.IssueLabels{
			"severity": "high",
			"type":     "feature",
			"area":     "security",
		}
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			Labels: &newLabels,
		})
		require.NoError(t, err)
		assert.Equal(t, issueID, updated.ID)

		// Verify changes were applied
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, newLabels, issue.Labels)
	})

	t.Run("update state with reason", func(t *testing.T) {
		newState := types.IssueStateBlocked
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			State:  &newState,
			Reason: ptr("Blocked for testing"),
		})
		require.NoError(t, err)
		assert.Equal(t, issueID, updated.ID)

		// Verify changes were applied
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, newState, issue.State)
	})

	t.Run("update state to ignored", func(t *testing.T) {
		newState := types.IssueStateIgnored
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			State:     &newState,
			Reason:    ptr("Ignoring for testing"),
			IgnoreFor: ptr("7 days"),
		})
		require.NoError(t, err)
		assert.Equal(t, issueID, updated.ID)

		// Verify changes were applied
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, newState, issue.State)
		assert.Equal(t, "7 days", issue.IgnoreFor)
	})

	t.Run("update with invalid event IDs", func(t *testing.T) {
		// Try to update with an event ID that doesn't exist
		randomEventID := uuid.New().String()
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			EventIDs: []string{randomEventID},
		})
		assertErrorType(t, err, types.ErrUnauthorizedEvents)

		// Verify the issue remains unchanged
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Len(t, issue.Events, 1, "Event count should remain unchanged")
		assert.Equal(t, eventID, issue.Events[0].ID, "Original event should still be present")
	})

	t.Run("update with duplicate event IDs", func(t *testing.T) {
		// Try to add the same event ID that's already associated with the issue
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			EventIDs: []string{eventID},
		})
		require.NoError(t, err, "Adding duplicate event ID should not cause an error")
		assert.Equal(t, issueID, updated.ID)

		// Verify the issue still has only one event (no duplicates)
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Len(t, issue.Events, 1, "Should still have only 1 event (no duplicates)")
		assert.Equal(t, eventID, issue.Events[0].ID)
	})

	t.Run("add multiple events including valid and duplicate", func(t *testing.T) {
		// Create a new event
		newEventID := setupEvent(ctx, t, client, agentID)

		// Try to update with a mix of new and existing event IDs
		updated, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			EventIDs: []string{eventID, newEventID},
		})
		require.NoError(t, err)
		assert.Equal(t, issueID, updated.ID)

		// Verify the issue now has both events (no duplicates)
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Len(t, issue.Events, 2, "Should have 2 distinct events")

		// Check that both event IDs are present
		eventIDs := []string{issue.Events[0].ID, issue.Events[1].ID}
		assert.Contains(t, eventIDs, eventID, "Original event should still be present")
		assert.Contains(t, eventIDs, newEventID, "New event should be added")
	})

	t.Run("mix of valid and invalid event IDs", func(t *testing.T) {
		// Create a new valid event
		validEventID := setupEvent(ctx, t, client, agentID)

		// Create a random invalid event ID
		invalidEventID := uuid.New().String()

		// Try to update with both valid and invalid event IDs
		_, err := client.UpdateIssue(ctx, issueID, types.UpdateIssue{
			EventIDs: []string{validEventID, invalidEventID},
		})
		assertErrorType(t, err, types.ErrUnauthorizedEvents)

		// Verify the issue remains unchanged (transaction should rollback)
		issue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Len(t, issue.Events, 2, "Event count should remain unchanged")
		assert.NotContains(t, []string{issue.Events[0].ID, issue.Events[1].ID}, validEventID,
			"Valid event should not be added due to transaction rollback")
	})
}

func TestDeleteIssue(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentID, _ := setupAgent(ctx, t, client)
	eventID := setupEvent(ctx, t, client, agentID)
	issueID := setupIssue(ctx, t, client, eventID)

	t.Run("invalid UUID", func(t *testing.T) {
		err := client.DeleteIssue(ctx, "not-a-uuid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue ID")
	})

	t.Run("not found", func(t *testing.T) {
		err := client.DeleteIssue(ctx, uuid.New().String())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ok", func(t *testing.T) {
		err := client.DeleteIssue(ctx, issueID)
		require.NoError(t, err)

		// Verify issue is no longer accessible
		_, err = client.Issue(ctx, issueID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

//nolint:gocognit,maintidx // This test function has high cognitive complexity due to multiple test cases
func TestIssues(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Setup GitHub agent
	githubAgentID, _ := setupAgent(ctx, t, client, WithAgentKind(types.AgentKindGithub))
	githubEventID := setupEvent(ctx, t, client, githubAgentID)

	// Create multiple issues with different attributes for testing
	setupTestIssues := func(t *testing.T) []string {
		t.Helper()
		issueIDs := make([]string, 0)

		// Issue 1: High priority, security class
		id1 := setupIssue(ctx, t, client, githubEventID,
			WithClass(types.IssueClassNetworkExfiltration),
			WithIssuePriority(types.IssuePriorityHigh),
			WithIssueState(types.IssueStateTriaged),
			WithIssueLabels(types.IssueLabels{
				"severity": "high",
				"type":     "security",
			}),
		)
		issueIDs = append(issueIDs, id1)

		// Issue 2: Medium priority, performance class
		id2 := setupIssue(ctx, t, client, githubEventID,
			WithClass(types.IssueClassCryptoMiner),
			WithIssuePriority(types.IssuePriorityMedium),
			WithIssueState(types.IssueStateBlocked),
			WithIssueLabels(types.IssueLabels{
				"severity": "medium",
				"type":     "performance",
			}),
		)
		issueIDs = append(issueIDs, id2)

		// Issue 3: Low priority, bug class
		id3 := setupIssue(ctx, t, client, githubEventID,
			WithClass(types.IssueClassNetworkExfiltration),
			WithIssuePriority(types.IssuePriorityLow),
			WithIssueState(types.IssueStateIgnored),
			WithIssueLabels(types.IssueLabels{
				"severity": "low",
				"type":     "bug",
			}),
		)
		issueIDs = append(issueIDs, id3)

		return issueIDs
	}

	t.Run("empty filters", func(t *testing.T) {
		issueIDs := setupTestIssues(t)

		result, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)
		assert.NotEmpty(t, result.Items)
		assert.GreaterOrEqual(t, len(result.Items), len(issueIDs))

		// Verify all created issues are present
		foundIDs := make(map[string]bool)
		for _, issue := range result.Items {
			foundIDs[issue.ID] = true
		}
		for _, id := range issueIDs {
			assert.True(t, foundIDs[id], "Expected issue %s not found in results", id)
		}
	})

	t.Run("filter by class", func(t *testing.T) {
		setupTestIssues(t)

		class := types.IssueClassNetworkExfiltration
		result, err := client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				Class: &class,
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, result.Items)

		for _, issue := range result.Items {
			assert.Equal(t, class, issue.Class)
		}
	})

	t.Run("filter by state", func(t *testing.T) {
		setupTestIssues(t)

		state := types.IssueStateTriaged
		result, err := client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				State: &state,
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, result.Items)

		for _, issue := range result.Items {
			assert.Equal(t, state, issue.State)
		}
	})

	t.Run("filter by priority", func(t *testing.T) {
		setupTestIssues(t)

		priority := types.IssuePriorityHigh
		result, err := client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				Priority: &priority,
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, result.Items)

		for _, issue := range result.Items {
			assert.Equal(t, priority, issue.Priority)
		}
	})

	t.Run("filter by labels", func(t *testing.T) {
		setupTestIssues(t)

		labels := types.IssueLabels{
			"severity": "high",
			"type":     "security",
		}
		result, err := client.Issues(ctx, types.ListIssues{
			Labels: labels,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, result.Items)

		for _, issue := range result.Items {
			for k, v := range labels {
				assert.Equal(t, v, issue.Labels[k])
			}
		}
	})

	t.Run("filter by agent kind", func(t *testing.T) {
		// Create test issues linked to GitHub agent
		githubIssueID := setupIssue(ctx, t, client, githubEventID,
			WithClass(types.IssueClassCryptoMiner),
			WithIssuePriority(types.IssuePriorityMedium),
			WithIssueState(types.IssueStateTriaged),
			WithIssueLabels(types.IssueLabels{
				"agent": "github",
			}),
		)

		agentKind := types.AgentKindGithub
		result, err := client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				AgentKind: &agentKind,
			},
			Labels: types.IssueLabels{"agent": "github"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, result.Items)

		// Verify returned issues have GitHub events
		foundIssue := false
		for _, issue := range result.Items {
			if issue.ID == githubIssueID {
				foundIssue = true
				// Verify events are from GitHub agent
				for _, event := range issue.Events {
					agent, err := client.Agent(ctx, event.AgentID)
					require.NoError(t, err)
					assert.Equal(t, types.AgentKindGithub, agent.Kind)
				}
			}
		}
		assert.True(t, foundIssue, "Expected to find GitHub issue")
	})

	t.Run("pagination", func(t *testing.T) {
		setupTestIssues(t)

		var firstPageSize uint = 2

		// Request first page
		firstPage, err := client.Issues(ctx, types.ListIssues{
			PageArgs: types.PageArgs{
				First: &firstPageSize,
			},
		})
		require.NoError(t, err)
		assert.Len(t, firstPage.Items, 2) // Using literal value instead of firstPageSize to avoid overflow warning
		assert.NotNil(t, firstPage.PageInfo.EndCursor)
		assert.True(t, firstPage.PageInfo.HasNextPage)

		// Request second page
		secondPage, err := client.Issues(ctx, types.ListIssues{
			PageArgs: types.PageArgs{
				First: &firstPageSize,
				After: firstPage.PageInfo.EndCursor,
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, secondPage.Items)

		// Verify no duplicates between pages
		firstPageIDs := make(map[string]bool)
		for _, issue := range firstPage.Items {
			firstPageIDs[issue.ID] = true
		}
		for _, issue := range secondPage.Items {
			assert.False(t, firstPageIDs[issue.ID], "Found duplicate issue %s in second page", issue.ID)
		}
	})

	t.Run("combined filters", func(t *testing.T) {
		// Create issues with specific attributes for GitHub agent
		githubHighPriorityID := setupIssue(ctx, t, client, githubEventID,
			WithClass(types.IssueClassNetworkExfiltration),
			WithIssuePriority(types.IssuePriorityHigh),
			WithIssueLabels(types.IssueLabels{
				"severity": "high",
				"agent":    "github",
				"type":     "security",
			}),
		)

		class := types.IssueClassNetworkExfiltration
		priority := types.IssuePriorityHigh
		agentKind := types.AgentKindGithub

		testCases := []struct {
			name        string
			filters     types.ListIssues
			expectedIDs []string
		}{
			{
				name: "high priority security issues from GitHub agent",
				filters: types.ListIssues{
					Filters: &types.IssueFilters{
						Class:     &class,
						Priority:  &priority,
						AgentKind: &agentKind,
					},
					Labels: types.IssueLabels{
						"severity": "high",
						"type":     "security",
					},
				},
				expectedIDs: []string{githubHighPriorityID},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := client.Issues(ctx, tc.filters)
				require.NoError(t, err)

				returnedIDs := make(map[string]bool)
				for _, issue := range result.Items {
					returnedIDs[issue.ID] = true

					// Verify each issue matches all specified filters
					if tc.filters.Filters != nil && tc.filters.Filters.Class != nil {
						assert.Equal(t, *tc.filters.Filters.Class, issue.Class)
					}
					if tc.filters.Filters != nil && tc.filters.Filters.Priority != nil {
						assert.Equal(t, *tc.filters.Filters.Priority, issue.Priority)
					}
					if tc.filters.Filters != nil && tc.filters.Filters.AgentKind != nil {
						hasMatchingAgent := false
						for _, event := range issue.Events {
							agent, err := client.Agent(ctx, event.AgentID)
							require.NoError(t, err)
							if agent.Kind == *tc.filters.Filters.AgentKind {
								hasMatchingAgent = true
								break
							}
						}
						assert.True(t, hasMatchingAgent)
					}
					for labelKey, labelValue := range tc.filters.Labels {
						assert.Equal(t, labelValue, issue.Labels[labelKey])
					}
				}

				// Verify expected issues are present
				for _, expectedID := range tc.expectedIDs {
					assert.True(t, returnedIDs[expectedID],
						"Expected issue %s not found in results", expectedID)
				}
			})
		}
	})

	t.Run("invalid filters", func(t *testing.T) {
		// Invalid state
		invalidState := types.IssueState("invalid")
		_, err := client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				State: &invalidState,
			},
		})
		require.Error(t, err)

		// Invalid priority
		invalidPriority := types.IssuePriority("invalid")
		_, err = client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				Priority: &invalidPriority,
			},
		})
		require.Error(t, err)

		// Invalid agent kind
		invalidKind := types.AgentKind("invalid")
		_, err = client.Issues(ctx, types.ListIssues{
			Filters: &types.IssueFilters{
				AgentKind: &invalidKind,
			},
		})
		require.Error(t, err)
	})

	t.Run("verify event data", func(t *testing.T) {
		issueIDs := setupTestIssues(t)

		result, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)

		for _, issue := range result.Items {
			if contains(issueIDs, issue.ID) {
				assert.NotEmpty(t, issue.Events)
				for _, event := range issue.Events {
					assert.NotEmpty(t, event.ID)
					assert.NotEmpty(t, event.AgentID)
					assert.NotNil(t, event.Data)
					assert.NotZero(t, event.CreatedAt)
					assert.NotZero(t, event.UpdatedAt)
				}
			}
		}
	})
}

// Helper function to check if a slice contains a string.
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
