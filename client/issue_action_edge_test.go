package client_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test edge case 3: Already-in-state actions.
// Tests that applying allow to already-allowed issues or block to already-blocked issues.
//
//nolint:dupl // Similar test structure is intentional for symmetry
func TestAlreadyInStateActions(t *testing.T) {
	ctx := t.Context()
	_, testClient := testclient.WithProjectTokenForTest(t)

	// Create an agent with GitHub context
	agentCreated, _ := setupAgent(ctx, t, testClient)
	eventID := setupNetworkDropEvent(ctx, t, testClient, agentCreated)

	t.Run("allow_already_allowed_issue", func(t *testing.T) {
		// Create an issue in allowed state
		issueID := setupIssue(ctx, t, testClient, eventID,
			WithClass(types.IssueClassNetworkExfiltration),
			WithIssueState(types.IssueStateAllowed),
		)

		// Verify initial state
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, issue.State)

		// Get history count before action
		initialHistory, err := testClient.IssueActionHistory(ctx, issueID)
		require.NoError(t, err)
		initialCount := len(initialHistory)

		// Attempt to allow an already allowed issue
		action := types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Trying to allow already allowed issue",
		}

		result, err := testClient.AllowIssue(ctx, issueID, action)
		require.NoError(t, err, "Should be able to allow an already allowed issue")
		assert.Equal(t, types.IssueStateAllowed, result.State, "State should remain allowed")

		// Verify action still recorded in history
		afterHistory, err := testClient.IssueActionHistory(ctx, issueID)
		require.NoError(t, err)
		assert.Greater(t, len(afterHistory), initialCount, "Action should be recorded in history even if state didn't change")
	})

	t.Run("block_already_blocked_issue", func(t *testing.T) {
		// Create an issue in blocked state
		issueID := setupIssue(ctx, t, testClient, eventID,
			WithClass(types.IssueClassNetworkExfiltration),
			WithIssueState(types.IssueStateBlocked),
		)

		// Verify initial state
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateBlocked, issue.State)

		// Get history count before action
		initialHistory, err := testClient.IssueActionHistory(ctx, issueID)
		require.NoError(t, err)
		initialCount := len(initialHistory)

		// Attempt to block an already blocked issue
		action := types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Trying to block already blocked issue",
		}

		result, err := testClient.BlockIssue(ctx, issueID, action)
		require.NoError(t, err, "Should be able to block an already blocked issue")
		assert.Equal(t, types.IssueStateBlocked, result.State, "State should remain blocked")

		// Verify action still recorded in history
		afterHistory, err := testClient.IssueActionHistory(ctx, issueID)
		require.NoError(t, err)
		assert.Greater(t, len(afterHistory), initialCount, "Action should be recorded in history even if state didn't change")
	})
}

// Test edge case 4: Permission boundaries.
// Tests actions on issues from different projects.
func TestPermissionBoundaries(t *testing.T) {
	ctx := t.Context()
	testClient := testclient.WithToken(t)

	// Create an agent and issue
	agentCreated, _ := setupAgent(ctx, t, testClient)
	eventID := setupNetworkDropEvent(ctx, t, testClient, agentCreated)
	issueID := setupIssue(ctx, t, testClient, eventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateBlocked),
	)

	t.Run("unauthorized_issue_action", func(t *testing.T) {
		// Try to perform action on a non-existent issue ID (simulating an issue from another project)
		randomID := uuid.New().String()
		_, err := testClient.AllowIssue(ctx, randomID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Should not be allowed on unauthorized issue",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied", "Should get permission denied for unknown issue")
	})

	t.Run("valid_issue_action", func(t *testing.T) {
		// Perform action on a valid issue from the same project
		_, err := testClient.AllowIssue(ctx, issueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Should be allowed on authorized issue",
		})
		require.NoError(t, err, "Should succeed on authorized issue")
	})
}

// Test edge case 5: GitHub context scopes.
// Tests that scopes are properly handled for different GitHub contexts.
func TestGitHubContextScopes(t *testing.T) {
	ctx := t.Context()
	testClient := testclient.WithToken(t)

	// Create a test GitHub context with repo and workflow info
	githubContext := &types.GitHubContext{
		Action:            "test-action",
		Actor:             "test-user",
		ActorID:           "12345",
		EventName:         "pull_request",
		Job:               "run",
		Ref:               "refs/pull/123/merge",
		RefName:           "123/merge",
		RefProtected:      false,
		RefType:           "branch",
		Repository:        "listendev/jibril",
		RepositoryID:      "test-repo-id",
		RepositoryOwner:   "listendev",
		RepositoryOwnerID: "87654321",
		RunAttempt:        "1",
		RunID:             "12345678901",
		RunNumber:         "100",
		RunnerArch:        "X64",
		RunnerOS:          "Linux",
		ServerURL:         "https://github.com",
		SHA:               "0123456789abcdef0123456789abcdef01234567",
		TriggeringActor:   "test-user",
		Workflow:          "test-workflow",
		WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
		WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	// Create an agent with GitHub context
	agentCreated, _ := setupAgent(ctx, t, testClient, WithGithubContext(githubContext))
	eventID := setupNetworkDropEvent(ctx, t, testClient, agentCreated)

	// Create issue
	issueID := setupIssue(ctx, t, testClient, eventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateBlocked),
	)

	t.Run("global_scope", func(t *testing.T) {
		result, err := testClient.AllowIssue(ctx, issueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Testing global scope",
		})
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, result.State)

		// Get issue to check its scope
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, *issue.PolicyScope)

		// Block for next test
		_, err = testClient.BlockIssue(ctx, issueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Blocking for next test",
		})
		require.NoError(t, err)
	})

	t.Run("repo_scope", func(t *testing.T) {
		result, err := testClient.AllowIssue(ctx, issueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeRepo,
			Reason: "Testing repo scope",
		})
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, result.State)

		// Get issue to check its scope
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyScopeRepo, *issue.PolicyScope)

		// Block for next test
		_, err = testClient.BlockIssue(ctx, issueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Blocking for next test",
		})
		require.NoError(t, err)
	})

	t.Run("workflow_scope", func(t *testing.T) {
		result, err := testClient.AllowIssue(ctx, issueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeWorkflow,
			Reason: "Testing workflow scope",
		})
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, result.State)

		// Get issue to check its scope
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyScopeWorkflow, *issue.PolicyScope)
	})
}

// Note: We've removed the TestZeroEvents test case since:.
// 1. The code already has proper validation in CreateIssue.Validate() requiring EventIDs
// 2. We've added validation in UpdateIssue.Validate() to prevent removal of all events
// 3. There are already service-layer checks in PerformIssueAction() to ensure issues have events
//    - It checks issue.ExtractNetworkDestination() which returns error for empty events
//    - It explicitly checks if len(issue.Events) == 0 and returns ErrNoAssociatedEvents

// These functions are already defined in issue_action_test.go
// We reference them here.
