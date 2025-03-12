package client_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testWorkflowName = "ci.yml" // Simulate workflow name for tests
)

// WithGitHubContextSimple sets a simplified GitHub context for the agent.
func WithGitHubContextSimple(owner, repo, repoID, workflow, runID, runAttempt string) AgentOption {
	return func(a *types.CreateAgent) {
		a.Kind = types.AgentKindGithub

		// Set default values for required fields if not provided
		if workflow == "" {
			workflow = "test-workflow"
		}
		if runID == "" {
			runID = "123456"
		}
		if runAttempt == "" {
			runAttempt = "1"
		}

		a.GithubContext = &types.GitHubContext{
			RepositoryOwner: owner,
			Repository:      repo,
			RepositoryID:    repoID,
			Workflow:        workflow,
			RunID:           runID,
			RunAttempt:      runAttempt,
			// Other required fields for validation
			Job:             "test-job",
			EventName:       "push",
			Action:          "run",
			Actor:           "test-user",
			ActorID:         "12345",
			RefName:         "main",
			RefType:         "branch",
			RunnerArch:      "X64",
			RunnerOS:        "Linux",
			ServerURL:       "https://github.com",
			SHA:             "0123456789abcdef0123456789abcdef01234567",
			TriggeringActor: "test-user",
		}
	}
}

// createAgentWithOptions creates an agent with custom options for testing.
func createAgentWithOptions(ctx context.Context, t *testing.T, client *client.Client, opts ...AgentOption) types.AgentCreated {
	t.Helper()

	// Default agent values
	agent := types.CreateAgent{
		OS:        "linux",
		Arch:      "amd64",
		Hostname:  "test-host",
		Version:   "1.0.0",
		IP:        "192.168.1.1",
		MachineID: uuid.New().String(),
		Labels:    types.AgentLabels{"env": "test"},
		Kind:      types.AgentKindGithub,
	}

	// Apply custom options
	for _, opt := range opts {
		opt(&agent)
	}

	created, err := client.CreateAgent(ctx, agent)
	require.NoError(t, err, "Failed to create agent")
	require.NotEmpty(t, created.ID, "Expected agent ID to be returned")
	require.NotEmpty(t, created.AgentToken, "Expected agent token to be returned")

	return created
}

// TestAgentNetworkPolicyRetrieval tests that agents correctly receive network policies.
func TestAgentNetworkPolicyRetrieval(t *testing.T) {
	t.Skip("Skipping network policy test until we fix all issues")
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Clean up existing policies first
	cleanupNetworkPolicies(ctx, t, client)

	repoID := uuid.New().String() // Simulate repository ID for tests
	workflowName := testWorkflowName

	// Setup test policies at all levels
	globalPolicyID := setupNetworkPolicy(ctx, t, client, WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal),
		WithNetworkPolicyConfig(types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeBoth,
			CIDRPolicy:    types.NetworkPolicyTypeDeny,
			ResolveMode:   types.NetworkPolicyResolveModeStrict,
			ResolvePolicy: types.NetworkPolicyTypeDeny,
		}),
		WithNetworkPolicyRules(
			types.CreateNetworkPolicyRule{
				Type:   types.NetworkPolicyRuleTypeDomain,
				Value:  "example.com",
				Action: types.NetworkPolicyTypeAllow,
			},
		),
	)

	// Store the repo policy ID for later use
	repoPolicyID := setupNetworkPolicy(ctx, t, client,
		WithNetworkPolicyScope(types.NetworkPolicyScopeRepo),
		WithNetworkPolicyRepositoryID(repoID),
		WithNetworkPolicyConfig(types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
			CIDRPolicy:    types.NetworkPolicyTypeDeny,
			ResolveMode:   types.NetworkPolicyResolveModsBypass,
			ResolvePolicy: types.NetworkPolicyTypeAllow,
		}),
		WithNetworkPolicyRules(
			types.CreateNetworkPolicyRule{
				Type:   types.NetworkPolicyRuleTypeCIDR,
				Value:  "192.168.0.0/16",
				Action: types.NetworkPolicyTypeAllow,
			},
		),
	)

	// Store the workflow policy ID for later use
	workflowPolicyID := setupNetworkPolicy(ctx, t, client,
		WithNetworkPolicyScope(types.NetworkPolicyScopeWorkflow),
		WithNetworkPolicyRepositoryID(repoID),
		WithNetworkPolicyWorkflowName(workflowName),
		WithNetworkPolicyConfig(types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeIPv6,
			CIDRPolicy:    types.NetworkPolicyTypeAllow,
			ResolveMode:   types.NetworkPolicyResolveModePermissive,
			ResolvePolicy: types.NetworkPolicyTypeDeny,
		}),
		WithNetworkPolicyRules(
			types.CreateNetworkPolicyRule{
				Type:   types.NetworkPolicyRuleTypeDomain,
				Value:  "github.com",
				Action: types.NetworkPolicyTypeAllow,
			},
		),
	)

	// For debugging
	t.Logf("Created policies - global: %s, repo: %s, workflow: %s",
		globalPolicyID, repoPolicyID, workflowPolicyID)

	// Create agents with different contexts and verify they receive correct policies
	t.Run("agent_with_no_context", func(t *testing.T) {
		// Create a GitHub agent without specific repo/workflow context
		agentCreated := createAgentWithOptions(ctx, t, client,
			WithGitHubContextSimple("owner", "repo", "", "", "", ""), // Empty repository ID
		)

		// Check network policy is included in agent creation response
		assert.NotNil(t, agentCreated.NetworkPolicy, "NetworkPolicy should be included in response")

		// Should receive only global policy
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, agentCreated.NetworkPolicy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, agentCreated.NetworkPolicy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModeStrict, agentCreated.NetworkPolicy.Config.ResolveMode)

		// Should have global rules only
		assert.Len(t, agentCreated.NetworkPolicy.Rules, 1)
		assert.Equal(t, "example.com", agentCreated.NetworkPolicy.Rules[0].Value)

		// Should include policy references
		assert.NotNil(t, agentCreated.NetworkPolicy.GlobalPolicy)
		assert.Nil(t, agentCreated.NetworkPolicy.RepoPolicy)
		assert.Nil(t, agentCreated.NetworkPolicy.WorkflowPolicy)
	})

	t.Run("agent_with_repo_context", func(t *testing.T) {
		// Create a GitHub agent with repository context
		agentCreated := createAgentWithOptions(ctx, t, client,
			WithGitHubContextSimple("owner", "repo", repoID, "", "", ""), // With repo ID, no workflow
		)

		// Check network policy is included in agent creation response
		assert.NotNil(t, agentCreated.NetworkPolicy, "NetworkPolicy should be included in response")

		// Should inherit from repo policy (override global)
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv4, agentCreated.NetworkPolicy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, agentCreated.NetworkPolicy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModsBypass, agentCreated.NetworkPolicy.Config.ResolveMode)

		// Should have global + repo rules
		assert.Len(t, agentCreated.NetworkPolicy.Rules, 2)

		// Should include policy references
		assert.NotNil(t, agentCreated.NetworkPolicy.GlobalPolicy)
		assert.NotNil(t, agentCreated.NetworkPolicy.RepoPolicy)
		assert.Equal(t, repoID, agentCreated.NetworkPolicy.RepoPolicy.RepositoryID)
		assert.Nil(t, agentCreated.NetworkPolicy.WorkflowPolicy)

		// Verify the agent model includes the network policy when retrieved directly
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		assert.NotNil(t, agent.NetworkPolicy)
	})

	t.Run("agent_with_workflow_context", func(t *testing.T) {
		// Create a GitHub agent with repository and workflow context
		agentCreated := createAgentWithOptions(ctx, t, client,
			WithGitHubContextSimple("owner", "repo", repoID, workflowName, "12345", "1"), // Full context
		)

		// Check network policy is included in agent creation response
		assert.NotNil(t, agentCreated.NetworkPolicy, "NetworkPolicy should be included in response")

		// Should inherit from workflow policy (override repo and global)
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv6, agentCreated.NetworkPolicy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, agentCreated.NetworkPolicy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModePermissive, agentCreated.NetworkPolicy.Config.ResolveMode)

		// Should have global + repo + workflow rules
		assert.Len(t, agentCreated.NetworkPolicy.Rules, 3)

		// Should include policy references
		assert.NotNil(t, agentCreated.NetworkPolicy.GlobalPolicy)
		assert.NotNil(t, agentCreated.NetworkPolicy.RepoPolicy)
		assert.NotNil(t, agentCreated.NetworkPolicy.WorkflowPolicy)
		assert.Equal(t, workflowName, agentCreated.NetworkPolicy.WorkflowPolicy.WorkflowName)

		// Verify the agent model includes the network policy when retrieved directly
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		assert.NotNil(t, agent.NetworkPolicy)
	})

	t.Run("update_global_policy_affects_agents", func(t *testing.T) {
		// Create an agent with no specific context
		agentCreated := createAgentWithOptions(ctx, t, client,
			WithGitHubContextSimple("owner", "repo", "", "", "", ""), // Empty repository ID
		)

		// Verify initial policy
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, agentCreated.NetworkPolicy.Config.CIDRMode)
		assert.Len(t, agentCreated.NetworkPolicy.Rules, 1)

		// Update global policy
		_, err := client.UpdateNetworkPolicy(ctx, globalPolicyID, types.UpdateNetworkPolicy{
			Config: &types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.NoError(t, err)

		// Add a new rule to the global policy
		_, err = client.CreateNetworkPolicyRule(ctx, globalPolicyID, types.CreateNetworkPolicyRule{
			Type:   types.NetworkPolicyRuleTypeCIDR,
			Value:  "10.0.0.0/8",
			Action: types.NetworkPolicyTypeAllow,
		})
		require.NoError(t, err)

		// Fetch agent and verify it has the updated policy
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		assert.NotNil(t, agent.NetworkPolicy)

		// Should have updated policy config
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv4, agent.NetworkPolicy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, agent.NetworkPolicy.Config.CIDRPolicy)

		// Should have both rules now
		assert.Len(t, agent.NetworkPolicy.Rules, 2)
	})

	t.Run("list_agents_includes_network_policies", func(t *testing.T) {
		// Create a few agents with different contexts
		createAgentWithOptions(ctx, t, client, WithGitHubContextSimple("owner1", "repo1", "", "", "", ""))
		createAgentWithOptions(ctx, t, client, WithGitHubContextSimple("owner2", "repo2", repoID, "", "", ""))
		createAgentWithOptions(ctx, t, client, WithGitHubContextSimple("owner3", "repo3", repoID, workflowName, "12345", "1"))

		// List all agents
		list, err := client.Agents(ctx, types.ListAgents{})
		require.NoError(t, err)
		assert.NotEmpty(t, list.Items)

		// Verify all agents have network policies
		for _, agent := range list.Items {
			if agent.Kind == types.AgentKindGithub {
				assert.NotNil(t, agent.NetworkPolicy, "All agents should have network policies")

				// Based on context, verify correct policy is applied
				if agent.GithubContext != nil {
					switch {
					case agent.GithubContext.RepositoryID == "":
						// Global policy only
						assert.Nil(t, agent.NetworkPolicy.RepoPolicy)
						assert.Nil(t, agent.NetworkPolicy.WorkflowPolicy)
					case agent.GithubContext.RepositoryID == repoID && agent.GithubContext.Workflow == "":
						// Repo policy
						assert.NotNil(t, agent.NetworkPolicy.RepoPolicy)
						assert.Nil(t, agent.NetworkPolicy.WorkflowPolicy)
					case agent.GithubContext.RepositoryID == repoID && agent.GithubContext.Workflow == workflowName:
						// Workflow policy
						assert.NotNil(t, agent.NetworkPolicy.RepoPolicy)
						assert.NotNil(t, agent.NetworkPolicy.WorkflowPolicy)
					}
				}
			}
		}
	})

	// Cleanup
	cleanupNetworkPolicies(ctx, t, client)
}

// TestAgentNetworkPolicyFallback tests that agents receive default policies when no policies exist.
func TestAgentNetworkPolicyFallback(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Clean up existing policies first
	cleanupNetworkPolicies(ctx, t, client)

	// Create an agent with no matching policies
	repoID := uuid.New().String()  // New repo ID with no policies
	workflowName := "new-workflow" // New workflow with no policies

	t.Run("agent_with_no_policies", func(t *testing.T) {
		// Create a GitHub agent with contexts that have no policies
		agentCreated := createAgentWithOptions(ctx, t, client,
			WithGitHubContextSimple("owner", "repo", repoID, workflowName, "12345", "1"),
		)

		// Should still receive a network policy with default values
		assert.NotNil(t, agentCreated.NetworkPolicy, "NetworkPolicy should be included in response")

		// Should have default config values
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, agentCreated.NetworkPolicy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, agentCreated.NetworkPolicy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModsBypass, agentCreated.NetworkPolicy.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, agentCreated.NetworkPolicy.Config.ResolvePolicy)

		// Should have no rules
		assert.Empty(t, agentCreated.NetworkPolicy.Rules)

		// Should have no policy references
		assert.Nil(t, agentCreated.NetworkPolicy.GlobalPolicy)
		assert.Nil(t, agentCreated.NetworkPolicy.RepoPolicy)
		assert.Nil(t, agentCreated.NetworkPolicy.WorkflowPolicy)
	})
}
