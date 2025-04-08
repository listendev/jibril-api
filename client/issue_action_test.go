package client_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupNetworkDropEvent creates a test event with network drop data.
func setupNetworkDropEvent(ctx context.Context, t *testing.T, testClient *client.Client, agentCreated types.AgentCreated) string {
	t.Helper()

	// Create a new client with the agent token
	agentClient := testClient.WithAgentToken(agentCreated.AgentToken)

	address := "203.0.113.1"

	// Create a drop_ip event with valid network destination
	dropIPEvent := types.CreateOrUpdateEvent{
		ID:      uuid.New().String(),
		AgentID: agentCreated.ID,
		Kind:    types.EventKindDropIP,
		Data: types.EventData{
			Dropped: &types.DroppedIP{
				Remote: &types.Node{
					Address: &address,
				},
				Proto: ptrStr("tcp"),
			},
			Process: &types.Process{
				Cmd:  ptrStr("curl"),
				PID:  ptrInt(1234),
				Exe:  ptrStr("/usr/bin/curl"),
				Args: ptrStr("curl malicious-site.com"),
			},
			Note: ptrStr("IP drop event"),
		},
	}

	// Add some debug checks
	if dropIPEvent.Data.Dropped == nil {
		t.Fatal("Dropped is nil")
	}
	if dropIPEvent.Data.Dropped.Remote == nil {
		t.Fatal("Dropped.Remote is nil")
	}
	if dropIPEvent.Data.Dropped.Remote.Address == nil {
		t.Fatal("Dropped.Remote.Address is nil")
	}
	if *dropIPEvent.Data.Dropped.Remote.Address == "" {
		t.Fatal("Dropped.Remote.Address is empty")
	}

	ingestedEvent, err := agentClient.IngestEvent(ctx, dropIPEvent)
	require.NoError(t, err, "Failed to ingest drop_ip event")
	require.NotZero(t, ingestedEvent.ID, "Expected event ID to be returned")
	return dropIPEvent.ID
}

//nolint:maintidx
func TestAllowIssue(t *testing.T) {
	ctx := t.Context()
	testClient := testclient.WithToken(t)

	// Create an agent with GitHub context to use for testing
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
		RepositoryID:      "repo-1234",
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

	agentCreated, _ := setupAgent(ctx, t, testClient, WithGithubContext(githubContext))

	// Create an event with network flow data
	eventID := setupNetworkDropEvent(ctx, t, testClient, agentCreated)

	// Create an issue in blocked state (no need for labels anymore)
	issueID := setupIssue(ctx, t, testClient, eventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateBlocked),
	)

	// Verify the issue has the event data properly loaded
	issue, err := testClient.Issue(ctx, issueID)
	if err != nil {
		t.Fatalf("Failed to get issue: %v", err)
	}

	t.Logf("Issue has %d events", len(issue.Events))
	for i, event := range issue.Events {
		t.Logf("Event[%d].Kind: %s", i, event.Kind)
		if event.Data.Dropped != nil && event.Data.Dropped.Remote != nil && event.Data.Dropped.Remote.Address != nil {
			t.Logf("Event[%d].Data.Dropped.Remote.Address: %s", i, *event.Data.Dropped.Remote.Address)
		} else {
			t.Logf("Event[%d] missing Dropped.Remote.Address", i)
		}
	}

	destType, destValue, err := issue.ExtractNetworkDestination()
	if err != nil {
		t.Logf("Failed to extract network destination: %v", err)
	} else {
		t.Logf("Network destination: %s %s", destType, destValue)
	}

	t.Run("invalid_uuid", func(t *testing.T) {
		_, err := testClient.AllowIssue(ctx, "not-a-uuid", types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Test allow",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue ID")
	})

	t.Run("unauthorized", func(t *testing.T) {
		// Using a random ID that should trigger unauthorized error
		randomID := uuid.New().String()
		_, err := testClient.AllowIssue(ctx, randomID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Test allow",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "permission denied")
	})

	t.Run("missing_scope", func(t *testing.T) {
		_, err := testClient.AllowIssue(ctx, issueID, types.IssueAction{
			Reason: "Test allow",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue action scope")
	})

	t.Run("missing_reason", func(t *testing.T) {
		_, err := testClient.AllowIssue(ctx, issueID, types.IssueAction{
			Scope: types.NetworkPolicyScopeGlobal,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue reason")
	})

	t.Run("allow_global_scope", func(t *testing.T) {
		// First, verify issue is in blocked state
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateBlocked, issue.State)

		// Allow at global scope
		action := types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Allow at global scope for testing",
		}

		result, err := testClient.AllowIssue(ctx, issueID, action)
		require.NoError(t, err)
		assert.Equal(t, issueID, result.ID)
		assert.Equal(t, types.IssueStateAllowed, result.State)
		assert.NotEmpty(t, result.NetworkPolicyID)
		assert.NotNil(t, result.NetworkPolicyRule)
		assert.Equal(t, types.NetworkPolicyTypeAllow, result.NetworkPolicyRule.Action)

		// Verify issue state was changed
		updatedIssue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, updatedIssue.State)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, *updatedIssue.PolicyScope)
		assert.NotEmpty(t, updatedIssue.NetworkPolicyID)
		assert.NotEmpty(t, updatedIssue.NetworkPolicyRuleID)
	})

	// Create another agent and issue for repository scope test
	repoContext := &types.GitHubContext{
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
		RepositoryID:      "repo-5678",
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
		Workflow:          "test-workflow-repo",
		WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
		WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	repoAgentCreated, _ := setupAgent(ctx, t, testClient, WithGithubContext(repoContext))
	repoEventID := setupNetworkDropEvent(ctx, t, testClient, repoAgentCreated)

	repoIssueID := setupIssue(ctx, t, testClient, repoEventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateBlocked),
	)

	t.Run("allow_repo_scope", func(t *testing.T) {
		// First, verify issue is in blocked state
		issue, err := testClient.Issue(ctx, repoIssueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateBlocked, issue.State)

		// Allow at repository scope
		action := types.IssueAction{
			Scope:  types.NetworkPolicyScopeRepo,
			Reason: "Allow at repository scope for testing",
		}

		result, err := testClient.AllowIssue(ctx, repoIssueID, action)
		require.NoError(t, err)
		assert.Equal(t, repoIssueID, result.ID)
		assert.Equal(t, types.IssueStateAllowed, result.State)
		assert.NotEmpty(t, result.NetworkPolicyID)
		assert.NotNil(t, result.NetworkPolicyRule)
		assert.Equal(t, types.NetworkPolicyTypeAllow, result.NetworkPolicyRule.Action)

		// Verify issue state was changed
		updatedIssue, err := testClient.Issue(ctx, repoIssueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, updatedIssue.State)
		assert.Equal(t, types.NetworkPolicyScopeRepo, *updatedIssue.PolicyScope)
		assert.NotEmpty(t, updatedIssue.NetworkPolicyID)
		assert.NotEmpty(t, updatedIssue.NetworkPolicyRuleID)

		// Get action history
		history, err := testClient.IssueActionHistory(ctx, repoIssueID)
		require.NoError(t, err)
		require.NotEmpty(t, history)
		assert.Equal(t, types.IssueActionTypeAllow, history[0].ActionType)
		assert.Equal(t, types.NetworkPolicyScopeRepo, history[0].Scope)
		assert.Equal(t, "Allow at repository scope for testing", history[0].Reason)
	})

	// Create another agent and issue for workflow scope test
	workflowContext := &types.GitHubContext{
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
		RepositoryID:      "repo-9012",
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
		Workflow:          "test-workflow-actual",
		WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
		WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	workflowAgentCreated, _ := setupAgent(ctx, t, testClient, WithGithubContext(workflowContext))
	workflowEventID := setupNetworkDropEvent(ctx, t, testClient, workflowAgentCreated)

	workflowIssueID := setupIssue(ctx, t, testClient, workflowEventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateBlocked),
	)

	t.Run("allow_workflow_scope", func(t *testing.T) {
		// Allow at workflow scope
		action := types.IssueAction{
			Scope:  types.NetworkPolicyScopeWorkflow,
			Reason: "Allow at workflow scope for testing",
		}

		result, err := testClient.AllowIssue(ctx, workflowIssueID, action)
		require.NoError(t, err)
		assert.Equal(t, workflowIssueID, result.ID)
		assert.Equal(t, types.IssueStateAllowed, result.State)
		assert.NotEmpty(t, result.NetworkPolicyID)
		assert.NotNil(t, result.NetworkPolicyRule)
		assert.Equal(t, types.NetworkPolicyTypeAllow, result.NetworkPolicyRule.Action)

		// Verify issue state was changed
		updatedIssue, err := testClient.Issue(ctx, workflowIssueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, updatedIssue.State)
		assert.Equal(t, types.NetworkPolicyScopeWorkflow, *updatedIssue.PolicyScope)
	})
}

func TestBlockIssue(t *testing.T) {
	ctx := t.Context()
	testClient := testclient.WithToken(t)

	// Create an agent with GitHub context to use for testing
	blockContext := &types.GitHubContext{
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
		RepositoryID:      "repo-4321",
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
		Workflow:          "test-workflow-block",
		WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
		WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	agentCreated, _ := setupAgent(ctx, t, testClient, WithGithubContext(blockContext))

	// Create an event with network flow data
	eventID := setupNetworkDropEvent(ctx, t, testClient, agentCreated)

	// Create an issue in allowed state
	issueID := setupIssue(ctx, t, testClient, eventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateAllowed),
	)

	t.Run("invalid_uuid", func(t *testing.T) {
		_, err := testClient.BlockIssue(ctx, "not-a-uuid", types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Test block",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue ID")
	})

	t.Run("block_global_scope", func(t *testing.T) {
		// First, verify issue is in allowed state
		issue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, issue.State)

		// Block at global scope
		action := types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "Block at global scope for testing",
		}

		result, err := testClient.BlockIssue(ctx, issueID, action)
		require.NoError(t, err)
		assert.Equal(t, issueID, result.ID)
		assert.Equal(t, types.IssueStateBlocked, result.State)
		assert.NotEmpty(t, result.NetworkPolicyID)
		assert.NotNil(t, result.NetworkPolicyRule)
		assert.Equal(t, types.NetworkPolicyTypeDeny, result.NetworkPolicyRule.Action)

		// Verify issue state was changed
		updatedIssue, err := testClient.Issue(ctx, issueID)
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateBlocked, updatedIssue.State)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, *updatedIssue.PolicyScope)

		// Get action history and verify details
		history, err := testClient.IssueActionHistory(ctx, issueID)
		require.NoError(t, err)
		require.NotEmpty(t, history)
		assert.Equal(t, types.IssueActionTypeBlock, history[0].ActionType)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, history[0].Scope)
	})

	// Create another agent and issue for testing multiple actions
	multiContext := &types.GitHubContext{
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
		RepositoryID:      "repo-multi",
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
		Workflow:          "test-workflow-multi",
		WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
		WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	multiAgentCreated, _ := setupAgent(ctx, t, testClient, WithGithubContext(multiContext))
	multiEventID := setupNetworkDropEvent(ctx, t, testClient, multiAgentCreated)

	multiActionIssueID := setupIssue(ctx, t, testClient, multiEventID,
		WithClass(types.IssueClassNetworkExfiltration),
		WithIssueState(types.IssueStateAllowed),
	)

	t.Run("multiple_actions", func(t *testing.T) {
		// First block the issue
		block1, err := testClient.BlockIssue(ctx, multiActionIssueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeGlobal,
			Reason: "First block at global scope",
		})
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateBlocked, block1.State)

		// Then allow it
		allow1, err := testClient.AllowIssue(ctx, multiActionIssueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeRepo,
			Reason: "Allow at repo scope",
		})
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateAllowed, allow1.State)

		// Then block it again
		block2, err := testClient.BlockIssue(ctx, multiActionIssueID, types.IssueAction{
			Scope:  types.NetworkPolicyScopeWorkflow,
			Reason: "Block at workflow scope",
		})
		require.NoError(t, err)
		assert.Equal(t, types.IssueStateBlocked, block2.State)

		// Check action history
		history, err := testClient.IssueActionHistory(ctx, multiActionIssueID)
		require.NoError(t, err)
		require.Len(t, history, 3, "Should have 3 action history entries")

		// History is returned in reverse chronological order (newest first)
		assert.Equal(t, types.IssueActionTypeBlock, history[0].ActionType)
		assert.Equal(t, types.NetworkPolicyScopeWorkflow, history[0].Scope)
		assert.Equal(t, "Block at workflow scope", history[0].Reason)

		assert.Equal(t, types.IssueActionTypeAllow, history[1].ActionType)
		assert.Equal(t, types.NetworkPolicyScopeRepo, history[1].Scope)
		assert.Equal(t, "Allow at repo scope", history[1].Reason)

		assert.Equal(t, types.IssueActionTypeBlock, history[2].ActionType)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, history[2].Scope)
		assert.Equal(t, "First block at global scope", history[2].Reason)
	})
}

func TestNetworkPolicyReuseAcrossWorkflows(t *testing.T) {
	ctx := t.Context()
	testClient := testclient.WithToken(t)

	// First agent with GitHub context for repository "test-repo-123"
	// Make sure to use the exact same repository ID string for consistency
	testRepoID := "test-repo-123"
	repoContext := &types.GitHubContext{
		Action:            "test-action",
		Actor:             "test-user",
		ActorID:           "12345",
		EventName:         "pull_request",
		Job:               "build",
		Ref:               "refs/pull/123/merge",
		Repository:        "listendev/test-repo",
		RepositoryID:      testRepoID,
		RepositoryOwner:   "listendev",
		RepositoryOwnerID: "87654321",
		RunID:             "run-12345",
		Workflow:          "build-workflow",
		WorkflowRef:       "listendev/test-repo/.github/workflows/build.yaml",
	}

	// Create first agent with the repository context
	agent1Created, _ := setupAgent(ctx, t, testClient, WithGithubContext(repoContext))

	// Create the drop_ip event using our helper function
	dropIPEventID := setupNetworkDropEvent(ctx, t, testClient, agent1Created)

	// Issue is created automatically

	// List issues to find the one created from our event
	issues, err := testClient.Issues(ctx, types.ListIssues{})
	require.NoError(t, err, "Failed to list issues")

	var issueID string
	for _, issue := range issues.Items {
		for _, event := range issue.Events {
			if event.ID == dropIPEventID {
				issueID = issue.ID
				break
			}
		}
		if issueID != "" {
			break
		}
	}

	require.NotEmpty(t, issueID, "Expected an issue to be created from the drop_ip event")

	// Verify the issue is in blocked state
	issue, err := testClient.Issue(ctx, issueID)
	require.NoError(t, err, "Failed to get issue")
	assert.Equal(t, types.IssueStateBlocked, issue.State, "Issue should be in blocked state")

	// Allow the IP at repository scope
	action := types.IssueAction{
		Scope:  types.NetworkPolicyScopeRepo,
		Reason: "This IP is required for our tests",
	}

	result, err := testClient.AllowIssue(ctx, issueID, action)
	require.NoError(t, err, "Failed to allow issue")
	assert.Equal(t, types.IssueStateAllowed, result.State, "Issue should be in allowed state")
	assert.Equal(t, types.NetworkPolicyTypeAllow, result.NetworkPolicyRule.Action, "Rule should be allow")
	assert.Equal(t, types.NetworkPolicyRuleTypeCIDR, result.NetworkPolicyRule.Type, "Rule should be for CIDR")
	assert.Equal(t, "203.0.113.1/32", result.NetworkPolicyRule.Value, "Rule should be for the correct IP")

	// Save the rule ID for later comparison
	ruleID := result.NetworkPolicyRule.ID
	networkPolicyID := result.NetworkPolicyID

	// Create second agent with same repository but different workflow
	workflow2Context := &types.GitHubContext{
		Action:            "test-action",
		Actor:             "test-user",
		ActorID:           "12345",
		EventName:         "pull_request",
		Job:               "test",
		Ref:               "refs/pull/123/merge",
		Repository:        "listendev/test-repo",
		RepositoryID:      testRepoID, // Same repository ID using the shared variable
		RepositoryOwner:   "listendev",
		RepositoryOwnerID: "87654321",
		RunID:             "run-67890",
		Workflow:          "test-workflow", // Different workflow
		WorkflowRef:       "listendev/test-repo/.github/workflows/test.yaml",
	}

	agent2Created, _ := setupAgent(ctx, t, testClient, WithGithubContext(workflow2Context))

	// Policy automatically propagates

	// Get the agent's network policy
	agent2WithPolicy, err := testClient.Agent(ctx, agent2Created.ID)
	require.NoError(t, err, "Failed to get agent with policy")
	require.NotNil(t, agent2WithPolicy.NetworkPolicy, "Agent should have network policy")

	// Print agent GitHub context for debugging
	t.Logf("Agent2 GitHub context: %+v", agent2WithPolicy.GithubContext)

	// Verify the network policy contains the previously created allow rule
	found := false

	// Log details for debugging
	t.Logf("Expected networkPolicyID: %s", networkPolicyID)
	t.Logf("Expected ruleID: %s", ruleID)

	// Log repo policy details
	if agent2WithPolicy.NetworkPolicy.RepoPolicy != nil {
		t.Logf("Agent has repo policy with ID: %s", agent2WithPolicy.NetworkPolicy.RepoPolicy.ID)
	} else {
		t.Logf("Agent does not have a repo policy")
	}

	// Log all rules
	t.Logf("Agent has %d network policy rules", len(agent2WithPolicy.NetworkPolicy.Rules))
	for i, rule := range agent2WithPolicy.NetworkPolicy.Rules {
		t.Logf("Rule[%d]: ID=%s, Action=%s, Type=%s, Value=%s",
			i, rule.ID, rule.Action, rule.Type, rule.Value)
	}

	// Access repo policy and rules
	if agent2WithPolicy.NetworkPolicy.RepoPolicy != nil &&
		agent2WithPolicy.NetworkPolicy.RepoPolicy.ID == networkPolicyID {
		// Check if any of the rules in the merged policy match the rule we created
		for _, rule := range agent2WithPolicy.NetworkPolicy.Rules {
			if rule.ID == ruleID {
				found = true
				assert.Equal(t, types.NetworkPolicyTypeAllow, rule.Action, "Rule should be allow")
				assert.Equal(t, types.NetworkPolicyRuleTypeCIDR, rule.Type, "Rule should be for CIDR")
				assert.Equal(t, "203.0.113.1/32", rule.Value, "Rule should be for the correct IP")
			}
		}
	}

	assert.True(t, found, "The second agent should have access to the network policy rule created for the first agent")
}

func TestIssueActionHistory(t *testing.T) {
	ctx := t.Context()
	testClient := testclient.WithToken(t)

	t.Run("invalid_uuid", func(t *testing.T) {
		_, err := testClient.IssueActionHistory(ctx, "not-a-uuid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issue ID")
	})

	t.Run("unauthorized", func(t *testing.T) {
		randomID := uuid.New().String()
		_, err := testClient.IssueActionHistory(ctx, randomID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "permission denied")
	})

	// Create a new issue with no actions
	agentCreated, _ := setupAgent(ctx, t, testClient)
	eventID := setupNetworkDropEvent(ctx, t, testClient, agentCreated)
	issueID := setupIssue(ctx, t, testClient, eventID)

	t.Run("no_actions", func(t *testing.T) {
		history, err := testClient.IssueActionHistory(ctx, issueID)
		require.NoError(t, err)
		assert.Empty(t, history, "New issue should have no actions")
	})
}

// Helper function to get a pointer to a string value.
func ptrStr(s string) *string {
	return &s
}

// Helper function to get a pointer to an int value.
func ptrInt(i int) *int {
	return &i
}
