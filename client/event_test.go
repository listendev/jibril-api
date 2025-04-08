package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
)

// Note: The ingestEvent function was removed since it's unused.

func TestIngestEvent(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// First create an agent to get a token
	agentCreated, _ := setupAgent(ctx, t, client)

	// Create a client with the agent token
	agentClient := client.WithAgentToken(agentCreated.AgentToken)

	t.Run("ok", func(t *testing.T) {
		event := types.CreateOrUpdateEvent{
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
		event := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: agentCreated.ID,
			Kind:    types.EventKind("invalid"),
		}

		_, err := agentClient.IngestEvent(ctx, event)
		assert.Error(t, err)
	})

	t.Run("missing agent id uses token agent id", func(t *testing.T) {
		// Submit an event with no agent ID specified
		event := types.CreateOrUpdateEvent{
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
					// Verify the event has the correct agent info
					assert.Equal(t, agentCreated.ID, e.Agent.ID, "Event should have agent ID from token")
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

	event := types.CreateOrUpdateEvent{
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

	webhookMockHandler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		defer r.Body.Close()
		var payload map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload))

		assert.NotEmpty(t, payload)
		w.WriteHeader(http.StatusOK)
	}

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

				// mock for webhook, just to check this event is creating issue and webhook is called
				ts := httptest.NewServer(http.HandlerFunc(webhookMockHandler))
				defer ts.Close()
				created, err := client.CreateWebhook(ctx, types.WebhookCreate{
					Name: "slack",
					URL:  ts.URL + "/test",
					Kind: types.WebhookKindSlack,
				})
				require.NoError(t, err)
				require.NotZero(t, created)

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

				// Verify the issue state based on the event kind
				expectedState := types.IssueStateAllowed
				if eventKind == types.EventKindDropIP || eventKind == types.EventKindDropDomain {
					expectedState = types.IssueStateBlocked
				}
				assert.Equal(t, expectedState, issue.State,
					"Issue for %s should have state '%s'", eventKind, expectedState)
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

// TestEventNetworkPolicyRuleLinking tests the automatic linking between blocked issues
// and network policy rules based on the destination of the events.
//
//nolint:gocognit,maintidx
func TestEventNetworkPolicyRuleLinking(t *testing.T) {
	// Using sequential tests to avoid race conditions
	// Each test gets a unique client/project environment with testclient.WithTestUser

	t.Run("IP_blocking", func(t *testing.T) {
		// Run sequentially to avoid race conditions
		ctx := t.Context()

		// Use a unique client (with unique project/org) for each test
		_, client := testclient.WithProjectTokenForTest(t)

		// First create an agent to get a token
		agentCreated, _ := setupAgent(ctx, t, client)

		// Create a client with the agent token for ingest operations
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Create a network policy with a deny rule for a specific IP
		// Using a unique IP to avoid any potential cross-test issues
		idBytes := uuid.New()
		lastOctet := 1 + (idBytes[0] % 254) // Use modulo to get a valid IP (1-254)
		testIP := fmt.Sprintf("203.0.113.%d", lastOctet)

		// Create a network policy with global scope
		policy := types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModePermissive,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
			Rules: []types.CreateNetworkPolicyRule{
				{
					Type:   types.NetworkPolicyRuleTypeCIDR,
					Value:  testIP + "/32",
					Action: types.NetworkPolicyTypeDeny,
				},
			},
		}

		// Create the policy using the admin client (not the agent client)
		createdPolicy, err := client.CreateNetworkPolicy(ctx, policy)
		require.NoError(t, err)
		require.NotEmpty(t, createdPolicy.ID)

		// Get the policy to retrieve the rule ID
		retrievedPolicy, err := client.NetworkPolicy(ctx, createdPolicy.ID)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(retrievedPolicy.Rules), 1)

		// Store the rule ID for later comparison
		ruleID := retrievedPolicy.Rules[0].ID

		// Create a DropIP event with the same IP as in the policy rule
		eventID := uuid.New().String()
		event := types.CreateOrUpdateEvent{
			ID:      eventID,
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test blocked IP event",
					Importance:  "high",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr(testIP),
					},
				},
			},
		}

		// Ingest the event using the agent client
		eventResult, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.Equal(t, eventID, eventResult.ID)

		// List issues to find the one that should have been auto-created
		// Use the admin client to ensure proper permissions
		issues, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)

		// Find the issue that was created from our event
		var issueID string
		for _, issue := range issues.Items {
			for _, e := range issue.Events {
				if e.ID == eventID {
					issueID = issue.ID
					break
				}
			}
			if issueID != "" {
				break
			}
		}

		// Make sure we found an issue
		require.NotEmpty(t, issueID, "Could not find issue created from our event")

		// Get the full issue directly to ensure we get the latest data
		fullIssue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)

		// Use the retrieved issue for our assertions
		createdIssue := &fullIssue

		// Assert that the issue was automatically created
		require.NotNil(t, createdIssue, "Issue should have been automatically created from the event")

		// Assert that the issue is in blocked state
		assert.Equal(t, types.IssueStateBlocked, createdIssue.State, "Issue should be in blocked state")

		// Assert that the issue is linked to the network policy rule
		assert.NotNil(t, createdIssue.NetworkPolicyID, "Issue should have a NetworkPolicyID")
		assert.NotNil(t, createdIssue.NetworkPolicyRuleID, "Issue should have a NetworkPolicyRuleID")
		assert.Equal(t, ruleID, *createdIssue.NetworkPolicyRuleID, "Issue should be linked to the correct network policy rule")

		assert.NotNil(t, createdIssue.PolicyScope, "Issue should have a PolicyScope")
		assert.Equal(t, types.NetworkPolicyScopeGlobal, *createdIssue.PolicyScope, "Issue should have the correct policy scope")

		// Clean up by deleting the network policy
		err = client.DeleteNetworkPolicy(ctx, createdPolicy.ID)
		require.NoError(t, err)
	})

	t.Run("Domain_blocking", func(t *testing.T) {
		// Run sequentially to avoid race conditions
		ctx := t.Context()

		// Use a unique client (with unique project/org) for each test
		_, client := testclient.WithProjectTokenForTest(t)

		// First create an agent to get a token
		agentCreated, _ := setupAgent(ctx, t, client)

		// Create a client with the agent token for ingest operations
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Create a network policy with a deny rule for a specific domain
		// Using UUID to ensure domain name is unique per test run
		testDomain := "test-" + uuid.New().String() + ".example.com"

		// Create a network policy with global scope
		policy := types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModePermissive,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
			Rules: []types.CreateNetworkPolicyRule{
				{
					Type:   types.NetworkPolicyRuleTypeDomain,
					Value:  testDomain,
					Action: types.NetworkPolicyTypeDeny,
				},
			},
		}

		// Create the policy using the admin client (not the agent client)
		createdPolicy, err := client.CreateNetworkPolicy(ctx, policy)
		require.NoError(t, err)
		require.NotEmpty(t, createdPolicy.ID)

		// Get the policy to retrieve the rule ID
		retrievedPolicy, err := client.NetworkPolicy(ctx, createdPolicy.ID)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(retrievedPolicy.Rules), 1)

		// Store the rule ID for later comparison
		ruleID := retrievedPolicy.Rules[0].ID

		// Create a DropDomain event with the same domain as in the policy rule
		eventID := uuid.New().String()
		event := types.CreateOrUpdateEvent{
			ID:      eventID,
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropDomain,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test blocked domain event",
					Importance:  "high",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Name: ptr(testDomain),
					},
				},
			},
		}

		// Ingest the event using the agent client
		eventResult, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.Equal(t, eventID, eventResult.ID)

		// List issues to find the one that should have been auto-created
		// Use the admin client to ensure proper permissions
		issues, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)

		// Find the issue that was created from our event
		var issueID string
		for _, issue := range issues.Items {
			for _, e := range issue.Events {
				if e.ID == eventID {
					issueID = issue.ID
					break
				}
			}
			if issueID != "" {
				break
			}
		}

		// Make sure we found an issue
		require.NotEmpty(t, issueID, "Could not find issue created from our event")

		// Get the full issue directly to ensure we get the latest data
		fullIssue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)

		// Use the retrieved issue for our assertions
		createdIssue := &fullIssue

		// Assert that the issue was automatically created
		require.NotNil(t, createdIssue, "Issue should have been automatically created from the event")

		// Assert that the issue is in blocked state
		assert.Equal(t, types.IssueStateBlocked, createdIssue.State, "Issue should be in blocked state")

		// Assert that the issue is linked to the network policy rule
		assert.NotNil(t, createdIssue.NetworkPolicyID, "Issue should have a NetworkPolicyID")
		assert.NotNil(t, createdIssue.NetworkPolicyRuleID, "Issue should have a NetworkPolicyRuleID")
		assert.Equal(t, ruleID, *createdIssue.NetworkPolicyRuleID, "Issue should be linked to the correct network policy rule")

		assert.NotNil(t, createdIssue.PolicyScope, "Issue should have a PolicyScope")
		assert.Equal(t, types.NetworkPolicyScopeGlobal, *createdIssue.PolicyScope, "Issue should have the correct policy scope")

		// Clean up by deleting the network policy
		err = client.DeleteNetworkPolicy(ctx, createdPolicy.ID)
		require.NoError(t, err)
	})

	t.Run("Repository_policy_blocking", func(t *testing.T) {
		// Run sequentially to avoid race conditions
		ctx := t.Context()

		// Force a unique test environment for this test
		_, client := testclient.WithProjectTokenForTest(t)

		// Print the project ID for debugging
		// Project ID comes from the project token

		// Create unique repository ID using UUID to avoid conflicts
		uniqueRepoID := "test-repo-" + uuid.New().String()

		// Create a network policy with a deny rule for a specific IP
		// Using a unique IP to avoid any potential cross-test issues
		idBytes := uuid.New()
		lastOctet := 1 + (idBytes[0] % 254) // Use modulo to get a valid IP (1-254)
		testIP := fmt.Sprintf("203.0.113.%d", lastOctet)

		// Create a network policy with repository scope
		policy := types.CreateNetworkPolicy{
			Scope:        types.NetworkPolicyScopeRepo,
			RepositoryID: uniqueRepoID, // Must match agent GitHub context
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModePermissive,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
			Rules: []types.CreateNetworkPolicyRule{
				{
					Type:   types.NetworkPolicyRuleTypeCIDR,
					Value:  testIP + "/32",
					Action: types.NetworkPolicyTypeDeny,
				},
			},
		}

		// Create the policy using the admin client
		createdPolicy, err := client.CreateNetworkPolicy(ctx, policy)
		require.NoError(t, err)
		require.NotEmpty(t, createdPolicy.ID)

		// Get the policy to retrieve the rule ID
		retrievedPolicy, err := client.NetworkPolicy(ctx, createdPolicy.ID)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(retrievedPolicy.Rules), 1)

		// Store the rule ID for later comparison
		ruleID := retrievedPolicy.Rules[0].ID

		// Create an agent with GitHub context (repository ID matching the policy's repo ID)
		repoCtx := &types.GitHubContext{
			Action:            "test-action",
			Actor:             "test-user",
			ActorID:           "12345",
			EventName:         "pull_request",
			Job:               "test-job",
			Ref:               "refs/pull/123/merge",
			Repository:        "listendev/test-repo",
			RepositoryID:      uniqueRepoID, // Using same ID as policy to ensure match
			RepositoryOwner:   "listendev",
			RepositoryOwnerID: "87654321",
			RunID:             "run-12345",
			Workflow:          "test-workflow",
			WorkflowRef:       "listendev/test-repo/.github/workflows/test.yaml",
		}

		// Create agent after policy to avoid creating duplicate policies
		agentCreated, _ := setupAgent(ctx, t, client, WithGithubContext(repoCtx))

		// Create a client with the agent token for ingest operations
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Create a DropIP event with the same IP as in the policy rule
		eventID := uuid.New().String()
		event := types.CreateOrUpdateEvent{
			ID:      eventID,
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropIP,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test blocked IP event (repo policy)",
					Importance:  "high",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Address: ptr(testIP),
					},
				},
			},
		}

		// Ingest the event using the agent client
		eventResult, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.Equal(t, eventID, eventResult.ID)

		// List issues to find the one that should have been auto-created
		// Use the admin client to ensure proper permissions
		issues, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)

		// Find the issue that was created from our event
		var issueID string
		for _, issue := range issues.Items {
			for _, e := range issue.Events {
				if e.ID == eventID {
					issueID = issue.ID
					break
				}
			}
			if issueID != "" {
				break
			}
		}

		// Make sure we found an issue
		require.NotEmpty(t, issueID, "Could not find issue created from our event")

		// Get the full issue directly to ensure we get the latest data
		fullIssue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)

		// Use the retrieved issue for our assertions
		createdIssue := &fullIssue

		// Assert that the issue was automatically created
		require.NotNil(t, createdIssue, "Issue should have been automatically created from the event")

		// Assert that the issue is in blocked state
		assert.Equal(t, types.IssueStateBlocked, createdIssue.State, "Issue should be in blocked state")

		// Assert that the issue is linked to the network policy rule
		assert.NotNil(t, createdIssue.NetworkPolicyID, "Issue should have a NetworkPolicyID")
		assert.NotNil(t, createdIssue.NetworkPolicyRuleID, "Issue should have a NetworkPolicyRuleID")
		assert.Equal(t, ruleID, *createdIssue.NetworkPolicyRuleID, "Issue should be linked to the correct network policy rule")

		assert.NotNil(t, createdIssue.PolicyScope, "Issue should have a PolicyScope")
		assert.Equal(t, types.NetworkPolicyScopeRepo, *createdIssue.PolicyScope, "Issue should have the correct policy scope (repo)")
	})

	t.Run("Workflow_policy_blocking", func(t *testing.T) {
		// Run sequentially to avoid race conditions
		ctx := t.Context()

		// Force a unique test environment for this test
		_, client := testclient.WithProjectTokenForTest(t)

		// Print the project ID for debugging
		// Project ID comes from the project token

		// Create unique IDs for repository and workflow to avoid conflicts
		uniqueRepoID := "test-repo-" + uuid.New().String()
		uniqueWorkflowName := "test-workflow-" + uuid.New().String()

		// Create an agent with GitHub context (repository ID and workflow are required for workflow policy)
		// This will auto-create both repository and workflow policies
		workflowCtx := &types.GitHubContext{
			Action:            "test-action",
			Actor:             "test-user",
			ActorID:           "12345",
			EventName:         "pull_request",
			Job:               "test-job",
			Ref:               "refs/pull/123/merge",
			Repository:        "listendev/test-repo",
			RepositoryID:      uniqueRepoID, // Using unique ID to prevent conflicts
			RepositoryOwner:   "listendev",
			RepositoryOwnerID: "87654321",
			RunID:             "run-67890",
			Workflow:          uniqueWorkflowName, // Using unique workflow name to prevent conflicts
			WorkflowRef:       "listendev/test-repo/.github/workflows/test.yaml",
		}

		// Creating an agent automatically creates a workflow policy since we're providing a GitHub context
		agentCreated, _ := setupAgent(ctx, t, client, WithGithubContext(workflowCtx))

		// Create a client with the agent token for ingest operations
		agentClient := client.WithAgentToken(agentCreated.AgentToken)

		// Find the auto-created workflow policy
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeWorkflow)
		require.NoError(t, err)

		// We know there must be at least one workflow policy
		require.NotEmpty(t, policies, "No workflow policies found")

		// Since the test environment is isolated, the only workflow policy should be ours
		// In a real environment with multiple policies, we would need to fetch each policy
		// and check its details to find the right one
		workflowPolicyID := policies[0].ID

		// Create a unique test domain using UUID to ensure domain name is unique per test run
		testDomain := "test-" + uuid.New().String() + ".example.com"

		// Add a rule to the existing policy
		ruleCreated, err := client.CreateNetworkPolicyRule(ctx, workflowPolicyID, types.CreateNetworkPolicyRule{
			Type:   types.NetworkPolicyRuleTypeDomain,
			Value:  testDomain,
			Action: types.NetworkPolicyTypeDeny,
		})
		require.NoError(t, err)
		require.NotEmpty(t, ruleCreated.ID)

		// Store the rule ID for later comparison
		ruleID := ruleCreated.ID

		// Create a DropDomain event with the same domain as in the policy rule
		eventID := uuid.New().String()
		event := types.CreateOrUpdateEvent{
			ID:      eventID,
			AgentID: agentCreated.ID,
			Kind:    types.EventKindDropDomain,
			Data: types.EventData{
				Head: &types.EventHead{
					Description: "Test blocked domain event (workflow policy)",
					Importance:  "high",
				},
				Dropped: &types.DroppedIP{
					Remote: &types.Node{
						Name: ptr(testDomain),
					},
				},
			},
		}

		// Ingest the event using the agent client
		eventResult, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.Equal(t, eventID, eventResult.ID)

		// List issues to find the one that should have been auto-created
		// Use the admin client to ensure proper permissions
		issues, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)

		// Find the issue that was created from our event
		var issueID string
		for _, issue := range issues.Items {
			for _, e := range issue.Events {
				if e.ID == eventID {
					issueID = issue.ID
					break
				}
			}
			if issueID != "" {
				break
			}
		}

		// Make sure we found an issue
		require.NotEmpty(t, issueID, "Could not find issue created from our event")

		// Get the full issue directly to ensure we get the latest data
		fullIssue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)

		// Use the retrieved issue for our assertions
		createdIssue := &fullIssue

		// Assert that the issue was automatically created
		require.NotNil(t, createdIssue, "Issue should have been automatically created from the event")

		// Assert that the issue is in blocked state
		assert.Equal(t, types.IssueStateBlocked, createdIssue.State, "Issue should be in blocked state")

		// Assert that the issue is linked to the network policy rule
		assert.NotNil(t, createdIssue.NetworkPolicyID, "Issue should have a NetworkPolicyID")
		assert.NotNil(t, createdIssue.NetworkPolicyRuleID, "Issue should have a NetworkPolicyRuleID")
		assert.Equal(t, ruleID, *createdIssue.NetworkPolicyRuleID, "Issue should be linked to the correct network policy rule")

		assert.NotNil(t, createdIssue.PolicyScope, "Issue should have a PolicyScope")
		assert.Equal(t, types.NetworkPolicyScopeWorkflow, *createdIssue.PolicyScope, "Issue should have the correct policy scope (workflow)")
	})
}

// TestAgentContextInEvents verifies that agent context information is correctly included in event responses.
func TestAgentContextInEvents(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("github_agent_context", func(t *testing.T) {
		// Create a GitHub agent with context for testing
		githubCtx := &types.GitHubContext{
			Action:            "test-action",
			Actor:             "test-user",
			ActorID:           "12345",
			EventName:         "pull_request",
			Job:               "test-job",
			Ref:               "refs/pull/123/merge",
			Repository:        "listendev/test-repo",
			RepositoryID:      "repo-67890",
			RepositoryOwner:   "listendev",
			RepositoryOwnerID: "87654321",
			RunID:             "run-12345",
			Workflow:          "test-workflow",
			WorkflowRef:       "listendev/test-repo/.github/workflows/test.yaml",
		}

		// Create agent with GitHub context
		githubAgent, _ := setupAgent(ctx, t, client, WithGithubContext(githubCtx))

		// Create a client with the agent token
		agentClient := client.WithAgentToken(githubAgent.AgentToken)

		// Create an event using the GitHub agent
		event := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: githubAgent.ID,
			Kind:    types.EventKindFlow,
			Data: types.EventData{
				Head: &types.EventHead{
					Name:        string(types.EventKindFlow),
					Description: "Flow event for GitHub context test",
					Importance:  "critical",
				},
			},
		}

		// Ingest the event
		eventResult, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.Equal(t, event.ID, eventResult.ID)

		// Wait for issue creation (since Flow events trigger issues)
		issues, err := client.Issues(ctx, types.ListIssues{})
		require.NoError(t, err)
		require.NotEmpty(t, issues.Items, "No issues created for flow event")

		// Find our issue and verify the event includes the agent with GitHub context
		var foundIssue bool
		var issueID string
		for _, issue := range issues.Items {
			for _, e := range issue.Events {
				if e.ID == event.ID {
					issueID = issue.ID
					foundIssue = true
					break
				}
			}
			if foundIssue {
				break
			}
		}
		require.True(t, foundIssue, "Could not find our event in any issue")

		// Get the full issue directly to ensure we get the latest data
		fullIssue, err := client.Issue(ctx, issueID)
		require.NoError(t, err)

		// Find our event in the issue
		var eventWithContext *types.Event
		for _, e := range fullIssue.Events {
			if e.ID == event.ID {
				eventWithContext = &e
				break
			}
		}
		require.NotNil(t, eventWithContext, "Event not found in issue")

		// Verify the agent and its GitHub context are properly included
		assert.Equal(t, githubAgent.ID, eventWithContext.Agent.ID, "Event should have correct agent ID")
		assert.Equal(t, types.AgentKindGithub, eventWithContext.Agent.Kind, "Agent should be GitHub kind")

		// Verify GitHub context is included and correct
		require.NotNil(t, eventWithContext.Agent.GithubContext, "GitHub context should be included")
		assert.Equal(t, githubCtx.Action, eventWithContext.Agent.GithubContext.Action)
		assert.Equal(t, githubCtx.Actor, eventWithContext.Agent.GithubContext.Actor)
		assert.Equal(t, githubCtx.ActorID, eventWithContext.Agent.GithubContext.ActorID)
		assert.Equal(t, githubCtx.EventName, eventWithContext.Agent.GithubContext.EventName)
		assert.Equal(t, githubCtx.Job, eventWithContext.Agent.GithubContext.Job)
		assert.Equal(t, githubCtx.Ref, eventWithContext.Agent.GithubContext.Ref)
		assert.Equal(t, githubCtx.Repository, eventWithContext.Agent.GithubContext.Repository)
		assert.Equal(t, githubCtx.RepositoryID, eventWithContext.Agent.GithubContext.RepositoryID)
		assert.Equal(t, githubCtx.RepositoryOwner, eventWithContext.Agent.GithubContext.RepositoryOwner)
		assert.Equal(t, githubCtx.RepositoryOwnerID, eventWithContext.Agent.GithubContext.RepositoryOwnerID)
		assert.Equal(t, githubCtx.RunID, eventWithContext.Agent.GithubContext.RunID)
		assert.Equal(t, githubCtx.Workflow, eventWithContext.Agent.GithubContext.Workflow)
		assert.Equal(t, githubCtx.WorkflowRef, eventWithContext.Agent.GithubContext.WorkflowRef)
	})

	t.Run("direct_event_retrieval", func(t *testing.T) {
		// This test verifies that direct event retrieval (not via an issue) also includes agent context
		// First create an agent with context
		githubCtx := &types.GitHubContext{
			Action:          "direct-test-action",
			Repository:      "listendev/direct-test-repo",
			RepositoryID:    "repo-direct-12345",
			RepositoryOwner: "listendev",
			Workflow:        "direct-test-workflow",
			// Required fields
			Job:   "direct-test-job",
			RunID: "direct-12345",
		}

		// Setup agent with GitHub context
		directAgent, _ := setupAgent(ctx, t, client, WithGithubContext(githubCtx))

		// Create a client with the agent token
		agentClient := client.WithAgentToken(directAgent.AgentToken)

		// Create an event that won't trigger issue creation (use a non-security event kind)
		event := types.CreateOrUpdateEvent{
			ID:      uuid.New().String(),
			AgentID: directAgent.ID,
			Kind:    types.EventKindAdultDomainAccess, // This kind doesn't trigger issue creation
			Data: types.EventData{
				Head: &types.EventHead{
					Name:        string(types.EventKindAdultDomainAccess),
					Description: "Adult domain event for direct retrieval test",
					Importance:  "low",
				},
			},
		}

		// Ingest the event
		eventResult, err := agentClient.IngestEvent(ctx, event)
		require.NoError(t, err)
		assert.Equal(t, event.ID, eventResult.ID)

		// TODO: Add direct event retrieval test if/when the API supports it
		// For now, we can verify through issues that contain our event

		// Create an issue manually with the event
		issue := types.CreateIssue{
			Class:       types.IssueClassNetworkExfiltration,
			Description: "Manual issue for direct event test",
			State:       types.IssueStateAllowed,
			Priority:    types.IssuePriorityMedium,
			EventIDs:    []string{event.ID},
		}

		// Create the issue
		issueCreated, err := client.CreateIssue(ctx, issue)
		require.NoError(t, err)
		require.NotEmpty(t, issueCreated.ID)

		// Fetch the issue to verify event context
		fullIssue, err := client.Issue(ctx, issueCreated.ID)
		require.NoError(t, err)

		// Find our event in the issue
		var eventWithContext *types.Event
		for _, e := range fullIssue.Events {
			if e.ID == event.ID {
				eventWithContext = &e
				break
			}
		}
		require.NotNil(t, eventWithContext, "Event not found in issue")

		// Verify agent context
		assert.Equal(t, directAgent.ID, eventWithContext.Agent.ID)
		assert.Equal(t, types.AgentKindGithub, eventWithContext.Agent.Kind)

		// Verify GitHub context is included and correct
		require.NotNil(t, eventWithContext.Agent.GithubContext, "GitHub context should be included")
		assert.Equal(t, githubCtx.Action, eventWithContext.Agent.GithubContext.Action)
		assert.Equal(t, githubCtx.Repository, eventWithContext.Agent.GithubContext.Repository)
		assert.Equal(t, githubCtx.RepositoryID, eventWithContext.Agent.GithubContext.RepositoryID)
		assert.Equal(t, githubCtx.RepositoryOwner, eventWithContext.Agent.GithubContext.RepositoryOwner)
		assert.Equal(t, githubCtx.Workflow, eventWithContext.Agent.GithubContext.Workflow)
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

			// We need to convert directly to CreateOrUpdateEvent
			// First unmarshal to a map to manipulate fields
			var rawEvent map[string]json.RawMessage
			err = json.Unmarshal(data, &rawEvent)
			require.NoError(t, err)

			// Create a CreateOrUpdateEvent with the same data
			event := types.CreateOrUpdateEvent{
				ID:      uuid.New().String(),
				AgentID: agentCreated.ID,
			}

			// Get kind
			var kind string
			err = json.Unmarshal(rawEvent["kind"], &kind)
			require.NoError(t, err)
			event.Kind = types.EventKind(kind)

			// Get data
			if dataRaw, ok := rawEvent["data"]; ok {
				err = json.Unmarshal(dataRaw, &event.Data)
				require.NoError(t, err)
			}

			// Ingest the event
			got, err := agentClient.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		})
	}
}
