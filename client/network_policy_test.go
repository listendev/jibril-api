package client_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// NetworkPolicyOption represents a function that modifies a CreateNetworkPolicy request.
type NetworkPolicyOption func(*types.CreateNetworkPolicy)

// WithNetworkPolicyScope sets the network policy scope.
func WithNetworkPolicyScope(scope types.NetworkPolicyScope) NetworkPolicyOption {
	return func(p *types.CreateNetworkPolicy) {
		p.Scope = scope
	}
}

// WithNetworkPolicyRepositoryID sets the repository ID for the network policy.
func WithNetworkPolicyRepositoryID(repositoryID string) NetworkPolicyOption {
	return func(p *types.CreateNetworkPolicy) {
		p.RepositoryID = repositoryID
	}
}

// WithNetworkPolicyWorkflowName sets the workflow name for the network policy.
func WithNetworkPolicyWorkflowName(workflowName string) NetworkPolicyOption {
	return func(p *types.CreateNetworkPolicy) {
		p.WorkflowName = workflowName
	}
}

// WithNetworkPolicyConfig sets the configuration for the network policy.
func WithNetworkPolicyConfig(config types.NetworkPolicyConfig) NetworkPolicyOption {
	return func(p *types.CreateNetworkPolicy) {
		p.Config = config
	}
}

// WithNetworkPolicyRules adds rules to the network policy.
func WithNetworkPolicyRules(rules ...types.CreateNetworkPolicyRule) NetworkPolicyOption {
	return func(p *types.CreateNetworkPolicy) {
		p.Rules = append(p.Rules, rules...)
	}
}

// setupNetworkPolicy creates a test network policy with the given options and returns the policy ID.
func setupNetworkPolicy(ctx context.Context, t *testing.T, client *client.Client, opts ...NetworkPolicyOption) string {
	t.Helper()

	// Create default policy (global scope)
	policy := types.CreateNetworkPolicy{
		Scope: types.NetworkPolicyScopeGlobal,
		Config: types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeBoth,
			CIDRPolicy:    types.NetworkPolicyTypeDeny,
			ResolveMode:   types.NetworkPolicyResolveModeStrict,
			ResolvePolicy: types.NetworkPolicyTypeDeny,
		},
	}

	// Apply all options
	for _, opt := range opts {
		opt(&policy)
	}

	// Create the policy
	created, err := client.CreateNetworkPolicy(ctx, policy)
	require.NoError(t, err, "Failed to create network policy")
	require.NotEmpty(t, created.ID, "Expected network policy ID to be returned")

	return created.ID
}

// TestCreateGlobalNetworkPolicy tests creating a global network policy.
func TestCreateGlobalNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("empty payload", func(t *testing.T) {
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{})
		require.Error(t, err)
	})

	t.Run("invalid scope", func(t *testing.T) {
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScope("invalid"),
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network policy scope")
	})

	t.Run("invalid CIDR mode", func(t *testing.T) {
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRMode("invalid"),
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network policy CIDR mode")
	})

	t.Run("invalid CIDR policy", func(t *testing.T) {
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyType("invalid"),
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network policy CIDR policy")
	})

	t.Run("invalid resolve mode", func(t *testing.T) {
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveMode("invalid"),
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network policy resolve mode")
	})

	t.Run("invalid resolve policy", func(t *testing.T) {
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyType("invalid"),
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network policy resolve policy")
	})

	t.Run("ok", func(t *testing.T) {
		// Delete any existing global policy first (since we can only have one)
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		policyCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, policyCreated.ID)
		assert.NotZero(t, policyCreated.CreatedAt)
		assert.NotZero(t, policyCreated.UpdatedAt)

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyCreated.ID)
		require.NoError(t, err)
	})

	t.Run("with rules", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy with rules
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal),
			WithNetworkPolicyConfig(types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			}),
			WithNetworkPolicyRules(
				types.CreateNetworkPolicyRule{
					Type:   types.NetworkPolicyRuleTypeCIDR,
					Value:  "192.168.1.0/24",
					Action: types.NetworkPolicyTypeAllow,
				},
				types.CreateNetworkPolicyRule{
					Type:   types.NetworkPolicyRuleTypeDomain,
					Value:  "github.com",
					Action: types.NetworkPolicyTypeAllow,
				},
			),
		)

		// Verify the policy was created with the rules
		policy, err := client.NetworkPolicy(ctx, policyID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, policy.Scope)
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, policy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, policy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModeStrict, policy.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, policy.Config.ResolvePolicy)

		// Verify rules
		assert.Len(t, policy.Rules, 2)

		// Check rules (order not guaranteed)
		foundCIDR := false
		foundDomain := false
		for _, rule := range policy.Rules {
			if rule.Type == types.NetworkPolicyRuleTypeCIDR {
				foundCIDR = true
				assert.Equal(t, "192.168.1.0/24", rule.Value)
				assert.Equal(t, types.NetworkPolicyTypeAllow, rule.Action)
			} else if rule.Type == types.NetworkPolicyRuleTypeDomain {
				foundDomain = true
				assert.Equal(t, "github.com", rule.Value)
				assert.Equal(t, types.NetworkPolicyTypeAllow, rule.Action)
			}
		}
		assert.True(t, foundCIDR, "Expected a CIDR rule")
		assert.True(t, foundDomain, "Expected a domain rule")

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)
	})

	t.Run("duplicate global policy", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create first global policy
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal))

		// Attempt to create a second global policy (should fail)
		_, err = client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope: types.NetworkPolicyScopeGlobal,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network policy already exists")

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)
	})
}

// TestGlobalNetworkPolicy tests retrieving a global network policy.
func TestGlobalNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("invalid UUID", func(t *testing.T) {
		_, err := client.NetworkPolicy(ctx, "not-a-uuid")
		require.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := client.NetworkPolicy(ctx, uuid.New().String())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("ok", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal))

		// Retrieve the policy
		policy, err := client.NetworkPolicy(ctx, policyID)
		require.NoError(t, err)
		assert.Equal(t, policyID, policy.ID)
		assert.Equal(t, types.NetworkPolicyScopeGlobal, policy.Scope)
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, policy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, policy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModeStrict, policy.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, policy.Config.ResolvePolicy)

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)
	})
}

// TestUpdateGlobalNetworkPolicy tests updating a global network policy.
func TestUpdateGlobalNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("invalid UUID", func(t *testing.T) {
		_, err := client.UpdateNetworkPolicy(ctx, "not-a-uuid", types.UpdateNetworkPolicy{
			Config: &types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := client.UpdateNetworkPolicy(ctx, uuid.New().String(), types.UpdateNetworkPolicy{
			Config: &types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.Error(t, err)
		// In test environment, non-existent policies will return permission denied
		// instead of not found because it checks permissions before checking existence
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("missing config", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal))

		// Try to update without a config
		_, err = client.UpdateNetworkPolicy(ctx, policyID, types.UpdateNetworkPolicy{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config is required")

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)
	})

	t.Run("invalid config", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal))

		// Try to update with invalid config
		_, err = client.UpdateNetworkPolicy(ctx, policyID, types.UpdateNetworkPolicy{
			Config: &types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRMode("invalid"),
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid network policy CIDR mode")

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal))

		// Update the policy
		updated, err := client.UpdateNetworkPolicy(ctx, policyID, types.UpdateNetworkPolicy{
			Config: &types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, policyID, updated.ID)
		assert.NotZero(t, updated.UpdatedAt)

		// Verify the update was applied
		policy, err := client.NetworkPolicy(ctx, policyID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv4, policy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, policy.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModsBypass, policy.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, policy.Config.ResolvePolicy)

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)
	})
}

// TestDeleteGlobalNetworkPolicy tests deleting a global network policy.
func TestDeleteGlobalNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("invalid UUID", func(t *testing.T) {
		err := client.DeleteNetworkPolicy(ctx, "not-a-uuid")
		require.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		err := client.DeleteNetworkPolicy(ctx, uuid.New().String())
		require.Error(t, err)
		// In test environment, non-existent policies will return permission denied
		// instead of not found because it checks permissions before checking existence
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("ok", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy
		policyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal))

		// Verify it exists
		_, err = client.NetworkPolicy(ctx, policyID)
		require.NoError(t, err)

		// Delete it
		err = client.DeleteNetworkPolicy(ctx, policyID)
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.NetworkPolicy(ctx, policyID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
	})
}

// Clean up any existing policies for clean test environment.
func cleanupNetworkPolicies(ctx context.Context, t *testing.T, client *client.Client) {
	t.Helper()

	// Clean up global policies
	policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
	require.NoError(t, err)
	for _, policy := range policies {
		err := client.DeleteNetworkPolicy(ctx, policy.ID)
		require.NoError(t, err, "Failed to delete existing global policy")
	}

	// Clean up repository policies
	policies, err = client.NetworkPolicies(ctx, types.NetworkPolicyScopeRepo)
	require.NoError(t, err)
	for _, policy := range policies {
		err := client.DeleteNetworkPolicy(ctx, policy.ID)
		require.NoError(t, err, "Failed to delete existing repo policy")
	}

	// Clean up workflow policies
	policies, err = client.NetworkPolicies(ctx, types.NetworkPolicyScopeWorkflow)
	require.NoError(t, err)
	for _, policy := range policies {
		err := client.DeleteNetworkPolicy(ctx, policy.ID)
		require.NoError(t, err, "Failed to delete existing workflow policy")
	}
}

// TestRepoNetworkPolicy tests repository-level network policy operations.
func TestRepoNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)
	repoID := uuid.New().String() // Simulate a repository ID

	// Clean up existing policies first
	cleanupNetworkPolicies(ctx, t, client)

	t.Run("create_repo_policy", func(t *testing.T) {
		policyCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope:        types.NetworkPolicyScopeRepo,
			RepositoryID: repoID,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
			Rules: []types.CreateNetworkPolicyRule{
				{
					Type:   types.NetworkPolicyRuleTypeCIDR,
					Value:  "192.168.0.0/16",
					Action: types.NetworkPolicyTypeAllow,
				},
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, policyCreated.ID)
		assert.NotZero(t, policyCreated.CreatedAt)
		assert.NotZero(t, policyCreated.UpdatedAt)

		// Verify via GET endpoint
		policy, err := client.NetworkPolicy(ctx, policyCreated.ID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyScopeRepo, policy.Scope)
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv4, policy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, policy.Config.CIDRPolicy)
		assert.Len(t, policy.Rules, 1)
		assert.Equal(t, types.NetworkPolicyRuleTypeCIDR, policy.Rules[0].Type)
		assert.Equal(t, "192.168.0.0/16", policy.Rules[0].Value)
	})

	t.Run("duplicate_repo_policy_fails", func(t *testing.T) {
		// Try to create a second policy for the same repo
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope:        types.NetworkPolicyScopeRepo,
			RepositoryID: repoID,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network policy already exists")
	})
}

// Using the testWorkflowName constant defined in agent_network_policy_test.go

// loadGoldenPolicy loads a golden policy file from the testdata directory.
func loadGoldenPolicy(t *testing.T, filename string) map[string]interface{} {
	t.Helper()

	// Read the golden file
	filepath := filepath.Join("testdata", "policies", filename)
	data, err := os.ReadFile(filepath)
	require.NoError(t, err, "Failed to read golden policy file: %s", filepath)

	// Parse the YAML into a map
	var policy map[string]interface{}
	err = yaml.Unmarshal(data, &policy)
	require.NoError(t, err, "Failed to parse golden policy file: %s", filepath)

	return policy
}

// TestWorkflowNetworkPolicy tests workflow-level network policy operations.
func TestWorkflowNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)
	repoID := uuid.New().String()    // Simulate a repository ID
	workflowName := testWorkflowName // Simulate a workflow name
	workflowName2 := "release.yml"   // Another workflow name for testing

	// Clean up existing policies first
	cleanupNetworkPolicies(ctx, t, client)

	t.Run("create_workflow_policy", func(t *testing.T) {
		policyCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope:        types.NetworkPolicyScopeWorkflow,
			RepositoryID: repoID,
			WorkflowName: workflowName,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeIPv6,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModePermissive,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			},
			Rules: []types.CreateNetworkPolicyRule{
				{
					Type:   types.NetworkPolicyRuleTypeDomain,
					Value:  "github.com",
					Action: types.NetworkPolicyTypeAllow,
				},
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, policyCreated.ID)

		// Verify via GET endpoint
		policy, err := client.NetworkPolicy(ctx, policyCreated.ID)
		require.NoError(t, err)
		assert.Equal(t, types.NetworkPolicyScopeWorkflow, policy.Scope)
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv6, policy.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyResolveModePermissive, policy.Config.ResolveMode)
		assert.Len(t, policy.Rules, 1)
		assert.Equal(t, types.NetworkPolicyRuleTypeDomain, policy.Rules[0].Type)
		assert.Equal(t, "github.com", policy.Rules[0].Value)
	})

	t.Run("same_repo_different_workflow", func(t *testing.T) {
		// Create a policy for a different workflow in the same repo
		policyCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope:        types.NetworkPolicyScopeWorkflow,
			RepositoryID: repoID,
			WorkflowName: workflowName2,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, policyCreated.ID)

		// Verify policies for both workflows exist
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeWorkflow)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(policies), 2)

		// Verify each workflow policy is unique
		found := make(map[string]bool)
		for _, policy := range policies {
			if policy.ID != "" {
				found[policy.ID] = true
			}
		}
		assert.Len(t, found, len(policies))
	})

	t.Run("duplicate_workflow_policy_fails", func(t *testing.T) {
		// Try to create a second policy for the same workflow
		_, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
			Scope:        types.NetworkPolicyScopeWorkflow,
			RepositoryID: repoID,
			WorkflowName: workflowName,
			Config: types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeBoth,
				CIDRPolicy:    types.NetworkPolicyTypeAllow,
				ResolveMode:   types.NetworkPolicyResolveModsBypass,
				ResolvePolicy: types.NetworkPolicyTypeAllow,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network policy already exists")
	})
}

// TestNetworkPolicyHierarchy tests the hierarchical merging of policies.
func TestNetworkPolicyHierarchy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)
	repoID := uuid.New().String()    // Simulate a repository ID
	workflowName := testWorkflowName // Simulate a workflow name

	// Clean up existing policies first
	cleanupNetworkPolicies(ctx, t, client)

	// Create policies at all levels with different configurations
	var globalPolicyID, repoPolicyID, workflowPolicyID string

	// 1. Create global policy
	globalCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
		Scope: types.NetworkPolicyScopeGlobal,
		Config: types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeBoth,
			CIDRPolicy:    types.NetworkPolicyTypeDeny,
			ResolveMode:   types.NetworkPolicyResolveModeStrict,
			ResolvePolicy: types.NetworkPolicyTypeDeny,
		},
		Rules: []types.CreateNetworkPolicyRule{
			{
				Type:   types.NetworkPolicyRuleTypeCIDR,
				Value:  "10.0.0.0/8",
				Action: types.NetworkPolicyTypeAllow,
			},
			{
				Type:   types.NetworkPolicyRuleTypeDomain,
				Value:  "example.com",
				Action: types.NetworkPolicyTypeAllow,
			},
		},
	})
	require.NoError(t, err)
	globalPolicyID = globalCreated.ID

	// 2. Create repository-level policy
	repoCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
		Scope:        types.NetworkPolicyScopeRepo,
		RepositoryID: repoID,
		Config: types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
			CIDRPolicy:    types.NetworkPolicyTypeAllow,
			ResolveMode:   types.NetworkPolicyResolveModsBypass,
			ResolvePolicy: types.NetworkPolicyTypeAllow,
		},
		Rules: []types.CreateNetworkPolicyRule{
			{
				Type:   types.NetworkPolicyRuleTypeCIDR,
				Value:  "192.168.0.0/16",
				Action: types.NetworkPolicyTypeAllow,
			},
			{
				Type:   types.NetworkPolicyRuleTypeDomain,
				Value:  "github.com",
				Action: types.NetworkPolicyTypeAllow,
			},
		},
	})
	require.NoError(t, err)
	repoPolicyID = repoCreated.ID

	// 3. Create workflow-level policy
	workflowCreated, err := client.CreateNetworkPolicy(ctx, types.CreateNetworkPolicy{
		Scope:        types.NetworkPolicyScopeWorkflow,
		RepositoryID: repoID,
		WorkflowName: workflowName,
		Config: types.NetworkPolicyConfig{
			CIDRMode:      types.NetworkPolicyCIDRModeIPv6,
			CIDRPolicy:    types.NetworkPolicyTypeDeny,
			ResolveMode:   types.NetworkPolicyResolveModePermissive,
			ResolvePolicy: types.NetworkPolicyTypeDeny,
		},
		Rules: []types.CreateNetworkPolicyRule{
			{
				Type:   types.NetworkPolicyRuleTypeCIDR,
				Value:  "2001:db8::/32",
				Action: types.NetworkPolicyTypeAllow,
			},
			{
				Type:   types.NetworkPolicyRuleTypeDomain,
				Value:  "npm.js",
				Action: types.NetworkPolicyTypeAllow,
			},
		},
	})
	require.NoError(t, err)
	workflowPolicyID = workflowCreated.ID

	t.Run("global_only", func(t *testing.T) {
		// Get merged policy with no repo or workflow specified
		merged, err := client.MergedNetworkPolicy(ctx, "", "")
		require.NoError(t, err)

		// Should only include global policy
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModeStrict, merged.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.ResolvePolicy)

		// Should contain global rules
		assert.Len(t, merged.Rules, 2)

		// Verify policy references
		assert.NotNil(t, merged.GlobalPolicy)
		assert.Equal(t, globalPolicyID, merged.GlobalPolicy.ID)
		assert.Nil(t, merged.RepoPolicy)
		assert.Nil(t, merged.WorkflowPolicy)
	})

	t.Run("repo_overrides_global", func(t *testing.T) {
		// Get merged policy with repo specified but no workflow
		merged, err := client.MergedNetworkPolicy(ctx, repoID, "")
		require.NoError(t, err)

		// Should override with repo policy config
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv4, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModsBypass, merged.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Config.ResolvePolicy)

		// Should contain global and repo rules (4 total)
		assert.Len(t, merged.Rules, 4)

		// Verify policy references
		assert.NotNil(t, merged.GlobalPolicy)
		assert.NotNil(t, merged.RepoPolicy)
		assert.Equal(t, repoID, merged.RepoPolicy.RepositoryID)
		assert.Equal(t, repoPolicyID, merged.RepoPolicy.ID)
		assert.Nil(t, merged.WorkflowPolicy)
	})

	t.Run("workflow_overrides_all", func(t *testing.T) {
		// Get merged policy with repo and workflow specified
		merged, err := client.MergedNetworkPolicy(ctx, repoID, workflowName)
		require.NoError(t, err)

		// Should override with workflow policy config
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv6, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModePermissive, merged.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.ResolvePolicy)

		// Should contain all rules (6 total)
		assert.Len(t, merged.Rules, 6)

		// Verify policy references
		assert.NotNil(t, merged.GlobalPolicy)
		assert.NotNil(t, merged.RepoPolicy)
		assert.NotNil(t, merged.WorkflowPolicy)
		assert.Equal(t, workflowName, merged.WorkflowPolicy.WorkflowName)
		assert.Equal(t, workflowPolicyID, merged.WorkflowPolicy.ID)
	})

	t.Run("remove_global_still_merges_others", func(t *testing.T) {
		// Delete global policy
		err = client.DeleteNetworkPolicy(ctx, globalPolicyID)
		require.NoError(t, err)

		// Get merged policy with repo and workflow
		merged, err := client.MergedNetworkPolicy(ctx, repoID, workflowName)
		require.NoError(t, err)

		// Should still use workflow config
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv6, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.CIDRPolicy)

		// Should only have 4 rules now (repo + workflow)
		assert.Len(t, merged.Rules, 4)

		// Verify policy references
		assert.Nil(t, merged.GlobalPolicy)
		assert.NotNil(t, merged.RepoPolicy)
		assert.NotNil(t, merged.WorkflowPolicy)
	})

	t.Run("remove_repo_still_merges_others", func(t *testing.T) {
		// Delete repo policy
		err = client.DeleteNetworkPolicy(ctx, repoPolicyID)
		require.NoError(t, err)

		// Get merged policy with repo and workflow
		merged, err := client.MergedNetworkPolicy(ctx, repoID, workflowName)
		require.NoError(t, err)

		// Should still use workflow config
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv6, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.CIDRPolicy)

		// Should only have 2 rules now (just workflow)
		assert.Len(t, merged.Rules, 2)

		// Verify policy references
		assert.Nil(t, merged.GlobalPolicy)
		assert.Nil(t, merged.RepoPolicy)
		assert.NotNil(t, merged.WorkflowPolicy)
	})

	t.Run("no_policies_returns_defaults", func(t *testing.T) {
		// Delete workflow policy
		err = client.DeleteNetworkPolicy(ctx, workflowPolicyID)
		require.NoError(t, err)

		// Get merged policy
		merged, err := client.MergedNetworkPolicy(ctx, repoID, workflowName)
		require.NoError(t, err)

		// Should use default config
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModsBypass, merged.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Config.ResolvePolicy)

		// Should have no rules
		assert.Empty(t, merged.Rules)

		// No policy references
		assert.Nil(t, merged.GlobalPolicy)
		assert.Nil(t, merged.RepoPolicy)
		assert.Nil(t, merged.WorkflowPolicy)
	})
}

// TestNetworkPolicyListPagination tests pagination for network policy list endpoint.

// TestMergedGlobalNetworkPolicy tests retrieving the merged network policy.
func TestMergedGlobalNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("global policy only", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Create a global policy with rules
		globalPolicyID := setupNetworkPolicy(ctx, t, client,
			WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal),
			WithNetworkPolicyConfig(types.NetworkPolicyConfig{
				CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
				CIDRPolicy:    types.NetworkPolicyTypeDeny,
				ResolveMode:   types.NetworkPolicyResolveModeStrict,
				ResolvePolicy: types.NetworkPolicyTypeDeny,
			}),
			WithNetworkPolicyRules(
				types.CreateNetworkPolicyRule{
					Type:   types.NetworkPolicyRuleTypeCIDR,
					Value:  "10.0.0.0/8",
					Action: types.NetworkPolicyTypeAllow,
				},
			),
		)

		// Get the merged policy (with no repo ID or workflow name)
		merged, err := client.MergedNetworkPolicy(ctx, "", "")
		require.NoError(t, err)

		// Verify only the global policy is included
		assert.Equal(t, types.NetworkPolicyCIDRModeIPv4, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModeStrict, merged.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeDeny, merged.Config.ResolvePolicy)

		// Verify rules
		assert.Len(t, merged.Rules, 1)
		assert.Equal(t, types.NetworkPolicyRuleTypeCIDR, merged.Rules[0].Type)
		assert.Equal(t, "10.0.0.0/8", merged.Rules[0].Value)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Rules[0].Action)

		// Verify global policy reference
		assert.NotNil(t, merged.GlobalPolicy)
		assert.Equal(t, globalPolicyID, merged.GlobalPolicy.ID)

		// Verify no repo or workflow policies
		assert.Nil(t, merged.RepoPolicy)
		assert.Nil(t, merged.WorkflowPolicy)

		// Cleanup
		err = client.DeleteNetworkPolicy(ctx, globalPolicyID)
		require.NoError(t, err)
	})

	t.Run("no policies", func(t *testing.T) {
		// Delete any existing global policy first
		policies, err := client.NetworkPolicies(ctx, types.NetworkPolicyScopeGlobal)
		require.NoError(t, err)

		for _, policy := range policies {
			err := client.DeleteNetworkPolicy(ctx, policy.ID)
			require.NoError(t, err, "Failed to delete existing global policy")
		}

		// Get the merged policy with no policies configured
		merged, err := client.MergedNetworkPolicy(ctx, "", "")
		require.NoError(t, err)

		// Verify default config is returned
		assert.Equal(t, types.NetworkPolicyCIDRModeBoth, merged.Config.CIDRMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Config.CIDRPolicy)
		assert.Equal(t, types.NetworkPolicyResolveModsBypass, merged.Config.ResolveMode)
		assert.Equal(t, types.NetworkPolicyTypeAllow, merged.Config.ResolvePolicy)

		// Verify no rules
		assert.Empty(t, merged.Rules)

		// Verify no policy references
		assert.Nil(t, merged.GlobalPolicy)
		assert.Nil(t, merged.RepoPolicy)
		assert.Nil(t, merged.WorkflowPolicy)
	})
}

// TestApiJibrilFormatGolden tests that the API returns policies that match the golden files.
// This test specifically ensures order-insensitive comparison of rules.
func TestApiJibrilFormatGolden(t *testing.T) { //nolint:gocognit
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Clean up existing policies first
	cleanupNetworkPolicies(ctx, t, client)

	// Test cases for different policy levels
	tests := []struct {
		name         string
		goldenFile   string
		createPolicy func(t *testing.T) (string, string, string) // returns policyID, repoID, workflowName
	}{
		{
			name:       "global_policy",
			goldenFile: "global_policy.yaml",
			createPolicy: func(t *testing.T) (string, string, string) {
				t.Helper()
				// Create a global policy that should match global_policy.yaml
				policyID := setupNetworkPolicy(ctx, t, client,
					WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal),
					WithNetworkPolicyConfig(types.NetworkPolicyConfig{
						CIDRMode:      types.NetworkPolicyCIDRModeBoth,
						CIDRPolicy:    types.NetworkPolicyTypeDeny,
						ResolveMode:   types.NetworkPolicyResolveModeStrict, // Will be mapped to "enforce"
						ResolvePolicy: types.NetworkPolicyTypeDeny,
					}),
					WithNetworkPolicyRules(
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeCIDR,
							Value:  "10.0.0.0/8",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeDomain,
							Value:  "example.com",
							Action: types.NetworkPolicyTypeAllow,
						},
					),
				)
				return policyID, "", "" // No repo or workflow for global policy
			},
		},
		{
			name:       "repo_policy",
			goldenFile: "repo_policy.yaml",
			createPolicy: func(t *testing.T) (string, string, string) {
				t.Helper()
				// Create repo policy that should match repo_policy.yaml
				repoID := uuid.New().String()
				policyID := setupNetworkPolicy(ctx, t, client,
					WithNetworkPolicyScope(types.NetworkPolicyScopeRepo),
					WithNetworkPolicyRepositoryID(repoID),
					WithNetworkPolicyConfig(types.NetworkPolicyConfig{
						CIDRMode:      types.NetworkPolicyCIDRModeIPv4, // Will be mapped to "alert" in Jibril format
						CIDRPolicy:    types.NetworkPolicyTypeAllow,
						ResolveMode:   types.NetworkPolicyResolveModsBypass,
						ResolvePolicy: types.NetworkPolicyTypeAllow,
					}),
					WithNetworkPolicyRules(
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeCIDR,
							Value:  "10.0.0.0/8",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeDomain,
							Value:  "example.com",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeCIDR,
							Value:  "192.168.0.0/16",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeDomain,
							Value:  "github.com",
							Action: types.NetworkPolicyTypeDeny,
						},
					),
				)
				return policyID, repoID, ""
			},
		},
		{
			name:       "workflow_policy",
			goldenFile: "workflow_policy.yaml",
			createPolicy: func(t *testing.T) (string, string, string) {
				t.Helper()
				// Create workflow policy that should match workflow_policy.yaml
				repoID := uuid.New().String()
				workflowName := "ci.yml"

				// Create a global policy first with some rules
				_ = setupNetworkPolicy(ctx, t, client,
					WithNetworkPolicyScope(types.NetworkPolicyScopeGlobal),
					WithNetworkPolicyConfig(types.NetworkPolicyConfig{
						CIDRMode:      types.NetworkPolicyCIDRModeBoth,
						CIDRPolicy:    types.NetworkPolicyTypeDeny,
						ResolveMode:   types.NetworkPolicyResolveModeStrict,
						ResolvePolicy: types.NetworkPolicyTypeDeny,
					}),
					WithNetworkPolicyRules(
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeCIDR,
							Value:  "10.0.0.0/8",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeDomain,
							Value:  "example.com",
							Action: types.NetworkPolicyTypeAllow,
						},
					),
				)

				// Create repo policy with additional rules
				_ = setupNetworkPolicy(ctx, t, client,
					WithNetworkPolicyScope(types.NetworkPolicyScopeRepo),
					WithNetworkPolicyRepositoryID(repoID),
					WithNetworkPolicyConfig(types.NetworkPolicyConfig{
						CIDRMode:      types.NetworkPolicyCIDRModeIPv4,
						CIDRPolicy:    types.NetworkPolicyTypeAllow,
						ResolveMode:   types.NetworkPolicyResolveModsBypass,
						ResolvePolicy: types.NetworkPolicyTypeAllow,
					}),
					WithNetworkPolicyRules(
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeCIDR,
							Value:  "192.168.0.0/16",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeDomain,
							Value:  "github.com",
							Action: types.NetworkPolicyTypeDeny,
						},
					),
				)

				// Create workflow policy with additional rules
				policyID := setupNetworkPolicy(ctx, t, client,
					WithNetworkPolicyScope(types.NetworkPolicyScopeWorkflow),
					WithNetworkPolicyRepositoryID(repoID),
					WithNetworkPolicyWorkflowName(workflowName),
					WithNetworkPolicyConfig(types.NetworkPolicyConfig{
						CIDRMode:      types.NetworkPolicyCIDRModeIPv6, // Will be mapped to "enforce" in Jibril format
						CIDRPolicy:    types.NetworkPolicyTypeDeny,
						ResolveMode:   types.NetworkPolicyResolveModePermissive, // Will be mapped to "alert" in Jibril format
						ResolvePolicy: types.NetworkPolicyTypeDeny,
					}),
					WithNetworkPolicyRules(
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeCIDR,
							Value:  "2001:db8::/32",
							Action: types.NetworkPolicyTypeAllow,
						},
						types.CreateNetworkPolicyRule{
							Type:   types.NetworkPolicyRuleTypeDomain,
							Value:  "npm.js",
							Action: types.NetworkPolicyTypeAllow,
						},
					),
				)

				return policyID, repoID, workflowName
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup the policy and get IDs
			policyID, repoID, workflowName := tt.createPolicy(t)

			// Make sure policy gets cleaned up after test
			defer func() {
				err := client.DeleteNetworkPolicy(ctx, policyID)
				require.NoError(t, err, "Failed to clean up test policy")
			}()

			// Get the policy in Jibril format
			jibrilFormat, err := client.MergedNetworkPolicyJibrilFormat(ctx, repoID, workflowName)
			require.NoError(t, err, "Failed to get policy in Jibril format")

			// Load the golden file
			goldenPolicy := loadGoldenPolicy(t, tt.goldenFile)

			// Convert to YAML format for consistent comparison
			yamlResult, err := yaml.Marshal(jibrilFormat)
			require.NoError(t, err, "Failed to marshal result to YAML")

			yamlGolden, err := yaml.Marshal(goldenPolicy)
			require.NoError(t, err, "Failed to marshal golden policy to YAML")

			// Parse back for structured comparison
			result := make(map[string]interface{})
			golden := make(map[string]interface{})

			err = yaml.Unmarshal(yamlResult, &result)
			require.NoError(t, err, "Failed to unmarshal result YAML")

			err = yaml.Unmarshal(yamlGolden, &golden)
			require.NoError(t, err, "Failed to unmarshal golden YAML")

			// Sort the rules for order-insensitive comparison
			sortRules := func(policy map[string]interface{}) {
				if np, ok := policy["network_policy"].(map[string]interface{}); ok {
					if rules, ok := np["rules"].([]interface{}); ok {
						// Sort the rules by type and value to ensure consistent ordering
						sort.Slice(rules, func(i, j int) bool {
							ruleI, okI := rules[i].(map[string]interface{})
							if !okI {
								return false
							}

							ruleJ, okJ := rules[j].(map[string]interface{})
							if !okJ {
								return false
							}

							// First check if it's a CIDR rule
							if cidrI, okI := ruleI["cidr"].(string); okI {
								if cidrJ, okJ := ruleJ["cidr"].(string); okJ {
									return cidrI < cidrJ
								}
								return true // CIDRs come before domains
							}

							// Then it must be a domain rule
							if domainI, okI := ruleI["domain"].(string); okI {
								if domainJ, okJ := ruleJ["domain"].(string); okJ {
									return domainI < domainJ
								}
								return false // Domains come after CIDRs
							}

							return false
						})
						np["rules"] = rules
					}
				}
			}

			// Sort rules in both result and golden
			sortRules(result)
			sortRules(golden)

			// Compare the two structures
			assert.Equal(t, golden, result, "API policy in Jibril format should match golden file %s", tt.goldenFile)
		})
	}
}
