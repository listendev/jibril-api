package client_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
)

// AgentOption represents a function that modifies a CreateAgent request.
type AgentOption func(*types.CreateAgent)

// WithOS sets the agent operating system.
func WithOS(os string) AgentOption {
	return func(a *types.CreateAgent) {
		a.OS = os
	}
}

// WithKubernetesContext sets the agent Kubernetes context.
func WithKubernetesContext(k8sContext *types.AgentKubernetesContext) AgentOption {
	return func(a *types.CreateAgent) {
		a.KubernetesContext = k8sContext
	}
}

// WithArch sets the agent architecture.
func WithArch(arch string) AgentOption {
	return func(a *types.CreateAgent) {
		a.Arch = arch
	}
}

// WithIP sets the agent IP address.
func WithIP(ip string) AgentOption {
	return func(a *types.CreateAgent) {
		a.IP = ip
	}
}

// WithMachineID sets the agent machine ID.
func WithMachineID(machineID string) AgentOption {
	return func(a *types.CreateAgent) {
		a.MachineID = machineID
	}
}

// WithLabels sets the agent labels.
func WithLabels(labels types.AgentLabels) AgentOption {
	return func(a *types.CreateAgent) {
		a.Labels = labels
	}
}

// WithGithubContext sets the agent GitHub context.
func WithGithubContext(githubContext *types.GitHubContext) AgentOption {
	return func(a *types.CreateAgent) {
		a.GithubContext = githubContext
	}
}

// WithHostname sets the agent hostname.
func WithHostname(hostname string) AgentOption {
	return func(a *types.CreateAgent) {
		a.Hostname = hostname
	}
}

// WithVersion sets the agent version.
func WithVersion(version string) AgentOption {
	return func(a *types.CreateAgent) {
		a.Version = version
	}
}

// WithAgentKind sets the agent kind.
func WithAgentKind(kind types.AgentKind) AgentOption {
	return func(a *types.CreateAgent) {
		a.Kind = kind
	}
}

// setupAgent creates a new agent with the given options and returns the agent created response and GitHub context.
func setupAgent(ctx context.Context, t *testing.T, client *client.Client, opts ...AgentOption) (types.AgentCreated, *types.GitHubContext) {
	t.Helper()

	// Create default GitHub context with all required fields
	githubContext := &types.GitHubContext{
		Action:            "test-action",
		Actor:             "test-user",
		ActorID:           "12345",
		EventName:         "pull_request",
		Job:               "run", // Required field
		Ref:               "refs/pull/123/merge",
		RefName:           "123/merge",
		RefProtected:      false,
		RefType:           "branch",
		Repository:        "listendev/jibril",
		RepositoryID:      "12345678",
		RepositoryOwner:   "listendev",
		RepositoryOwnerID: "87654321",
		RunAttempt:        "1",
		RunID:             "12345678901", // Required field
		RunNumber:         "100",
		RunnerArch:        "X64",
		RunnerOS:          "Linux",
		ServerURL:         "https://github.com",
		SHA:               "0123456789abcdef0123456789abcdef01234567",
		TriggeringActor:   "test-user",
		Workflow:          "Test Workflow", // Required field
		WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
		WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	// Create default agent configuration with GitHub context
	agent := types.CreateAgent{
		OS:            "linux",
		Arch:          "amd64",
		Hostname:      "test-host",
		Version:       "1.0.0",
		IP:            "10.0.0.1",
		MachineID:     "test-machine-id-" + uuid.New().String(),
		Labels:        types.AgentLabels{},
		Kind:          types.AgentKindGithub,
		GithubContext: githubContext,
	}

	// Apply all options
	for _, opt := range opts {
		opt(&agent)
	}

	// Create the agent
	agentCreated, err := client.CreateAgent(ctx, agent)
	require.NoError(t, err, "Failed to create agent")
	require.NotEmpty(t, agentCreated.ID, "Expected agent ID to be returned")

	return agentCreated, githubContext
}

func TestAgentCreate(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("empty payload", func(t *testing.T) {
		_, err := client.CreateAgent(ctx, types.CreateAgent{})
		require.Error(t, err)
	})

	t.Run("invalid kind", func(t *testing.T) {
		// For the invalid kind case, we still need to use direct API call
		// since our setupAgent function enforces valid defaults
		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:            "linux",
			Arch:          "amd64",
			Hostname:      "jenkins",
			Version:       "1.0.0",
			IP:            "192.168.0.1",
			MachineID:     "1234",
			Labels:        types.AgentLabels{},
			Kind:          "invalid", // Invalid kind forces error
			GithubContext: &types.GitHubContext{Job: "test-job", RunID: "12345", Workflow: "test-workflow"},
		})
		require.Error(t, err)
	})

	t.Run("basic agent", func(t *testing.T) {
		// Create a basic agent using our setup helper
		agentCreated, githubContext := setupAgent(ctx, t, client)

		// Verify the agent was created successfully
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		require.Equal(t, "linux", agent.OS)                            // Default OS
		require.Equal(t, "amd64", agent.Arch)                          // Default arch
		require.Equal(t, githubContext.Repository, "listendev/jibril") // Verify github context
	})

	t.Run("with custom options", func(t *testing.T) {
		agentCreated, _ := setupAgent(ctx, t, client,
			WithOS("windows"),
			WithArch("arm64"),
			WithIP("192.168.1.100"),
			WithLabels(types.AgentLabels{"env": "testing", "region": "us-west"}),
			WithHostname("custom-host"),
			WithVersion("2.0.0"),
		)

		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		require.Equal(t, "windows", agent.OS)
		require.Equal(t, "arm64", agent.Arch)
		require.Equal(t, "192.168.1.100/32", agent.IP)
		require.Equal(t, "custom-host", agent.Hostname)
		require.Equal(t, "2.0.0", agent.Version)
		require.Equal(t, "testing", agent.Labels["env"])
		require.Equal(t, "us-west", agent.Labels["region"])
	})

	var vanillaID string
	t.Run("vanilla agent", func(t *testing.T) {
		created, err := client.CreateAgent(ctx, types.CreateAgent{
			ProjectID: "1234",
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "jenkins",
			Version:   "1.0.0",
			IP:        "192.168.0.1",
			MachineID: "1234",
			Labels:    types.AgentLabels{},
			Kind:      "vanilla",
			VanillaContext: &types.AgentVanillaContext{
				Job:       "test-job",
				RunnerOS:  "linux",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		})

		require.NoError(t, err, "Failed to create vanilla agent")

		vanillaID = created.ID
	})

	t.Run("get vanilla agent", func(t *testing.T) {
		agent, err := client.Agent(ctx, vanillaID)
		require.NoError(t, err, "Failed to get vanilla agent")
		require.Equal(t, "vanilla", agent.Kind.String())
	})

	t.Run("vanilla agent update", func(t *testing.T) {
		err := client.UpdateAgent(ctx, vanillaID, types.UpdateAgent{
			MachineID: ptr("updated-machine-id"),
		})
		require.NoError(t, err, "Failed to update vanilla agent")

		// Verify update was applied
		agent, err := client.Agent(ctx, vanillaID)
		require.NoError(t, err)
		require.Equal(t, "updated-machine-id", agent.MachineID)
	})
}

func TestAgentGet(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create an agent with custom settings
	agentCreated, _ := setupAgent(ctx, t, client,
		WithOS("debian"),
		WithArch("amd64"),
		WithLabels(types.AgentLabels{"service": "api"}),
	)

	t.Run("invalid uuid", func(t *testing.T) {
		_, err := client.Agent(ctx, "1234")
		require.Error(t, err)
	})

	t.Run("not found or unauthorized", func(t *testing.T) {
		_, err := client.Agent(ctx, uuid.NewString())
		require.Error(t, err)
		// Since we now check authorization before existence, random UUIDs will return "permission denied"
		require.Contains(t, err.Error(), "permission denied")
	})

	t.Run("unauthorized", func(t *testing.T) {
		// Using a random ID that should trigger unauthorized error
		randomID := uuid.NewString()
		_, err := client.Agent(ctx, randomID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "permission denied")
	})

	t.Run("valid agent", func(t *testing.T) {
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		require.Equal(t, agentCreated.ID, agent.ID)
		require.Equal(t, "debian", agent.OS)
		require.Equal(t, "amd64", agent.Arch)
		require.Equal(t, "api", agent.Labels["service"])
	})
}

func TestAgentUpdate(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentCreated, _ := setupAgent(ctx, t, client,
		WithLabels(types.AgentLabels{"original": "value"}),
	)

	t.Run("no fields", func(t *testing.T) {
		err := client.UpdateAgent(ctx, agentCreated.ID, types.UpdateAgent{})
		require.Error(t, err)
	})

	t.Run("unauthorized", func(t *testing.T) {
		// Using a random ID that should trigger unauthorized error
		randomID := uuid.NewString()
		err := client.UpdateAgent(ctx, randomID, types.UpdateAgent{
			MachineID: ptr("should-not-update"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "permission denied")
	})

	t.Run("update machine id", func(t *testing.T) {
		err := client.UpdateAgent(ctx, agentCreated.ID, types.UpdateAgent{
			MachineID: ptr("updated-machine-id"),
		})
		require.NoError(t, err)

		// Verify update was applied
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		require.Equal(t, "updated-machine-id", agent.MachineID)
	})
}

func TestAgentDelete(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentCreated, _ := setupAgent(ctx, t, client)

	t.Run("invalid uuid", func(t *testing.T) {
		err := client.DeleteAgent(ctx, "1234")
		require.Error(t, err)
	})

	t.Run("not found or unauthorized", func(t *testing.T) {
		err := client.DeleteAgent(ctx, uuid.NewString())
		require.Error(t, err)
		// Since we now check authorization before existence, random UUIDs will return "permission denied"
		require.Contains(t, err.Error(), "permission denied")
	})

	t.Run("unauthorized", func(t *testing.T) {
		// Using a random ID that should trigger unauthorized error
		randomID := uuid.NewString()
		err := client.DeleteAgent(ctx, randomID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "permission denied")
	})

	t.Run("success", func(t *testing.T) {
		// Delete the agent - this should NOT return an error
		err := client.DeleteAgent(ctx, agentCreated.ID)
		require.NoError(t, err, "Expected successful deletion")

		// Verify agent was deleted by trying to get it
		_, err = client.Agent(ctx, agentCreated.ID)
		require.Error(t, err, "Expected error when retrieving deleted agent")
	})
}

// Test label constants.
const (
	labelKeyValue1 = "value1"
	labelKeyValue2 = "value2"
	labelKey1      = "key1"
	labelKey2      = "key2"
)

func TestAgentList(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create agents with different properties
	setupAgent(ctx, t, client,
		WithOS("debian"),
		WithIP("192.168.0.1"),
		WithLabels(types.AgentLabels{labelKey2: labelKeyValue2}),
	)

	setupAgent(ctx, t, client,
		WithOS("ubuntu"),
		WithIP("192.168.0.2"),
		WithLabels(types.AgentLabels{labelKey1: labelKeyValue1}),
	)

	t.Run("no filters", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.Items), 2)
		require.NotNil(t, resp.PageInfo.StartCursor)
		require.NotNil(t, resp.PageInfo.EndCursor)
	})

	t.Run("filter by os", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{
			Filters: &types.AgentFilters{OS: ptr("ubuntu")},
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.Items), 1)
		require.Equal(t, "ubuntu", resp.Items[0].OS)
	})

	t.Run("filter by ip", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{
			Filters: &types.AgentFilters{IP: ptr("192.168.0.1")},
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.Items), 1)

		// Check if the IP starts with our expected value
		// This handles both "192.168.0.1" and "192.168.0.1/32" format
		require.True(t, len(resp.Items) > 0 && resp.Items[0].IP != "")
		require.True(t,
			strings.HasPrefix(resp.Items[0].IP, "192.168.0.1"),
			"Expected IP to start with 192.168.0.1, got %s", resp.Items[0].IP,
		)
	})

	t.Run("filter by labels", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{
			Labels: types.AgentLabels{
				labelKey1: labelKeyValue1,
			},
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.Items), 1)
		for _, agent := range resp.Items {
			if agent.Labels[labelKey1] == labelKeyValue1 {
				return // Success
			}
		}
		t.Fatalf("Expected to find at least one agent with label %s=%s", labelKey1, labelKeyValue1)
	})
}

// TestAgentLabelsValidation tests the validation of agent labels.
// It checks various validation cases including valid labels, invalid formats,.
// length limits, and filtering operations.
func TestAgentLabelsValidation(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create valid agent with valid labels
	t.Run("valid labels", func(t *testing.T) {
		validLabels := types.AgentLabels{
			"app":         "api",
			"environment": "production",
			"version":     "1.2.3",
			"tier":        "frontend",
			"region":      "us-west-2",
		}

		agentCreated, _ := setupAgent(ctx, t, client, WithLabels(validLabels))

		// Verify the agent was created and labels were saved
		agent, err := client.Agent(ctx, agentCreated.ID)
		require.NoError(t, err)
		assert.Equal(t, "api", agent.Labels["app"])
		assert.Equal(t, "production", agent.Labels["environment"])
		assert.Equal(t, "1.2.3", agent.Labels["version"])
		assert.Equal(t, "frontend", agent.Labels["tier"])
		assert.Equal(t, "us-west-2", agent.Labels["region"])
	})

	// Test invalid label key format
	t.Run("invalid label key format", func(t *testing.T) {
		invalidLabels := types.AgentLabels{
			"-invalid-key": "value", // Key starts with dash
		}

		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "test-host",
			Version:   "1.0.0",
			IP:        "192.168.1.1", // Add required IP field
			MachineID: "test-machine-id",
			Labels:    invalidLabels,
			Kind:      types.AgentKindGithub,
			GithubContext: &types.GitHubContext{
				Job:      "test-job",
				RunID:    "12345",
				Workflow: "test-workflow",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid label key format")
	})

	// Test invalid label value format
	t.Run("invalid label value format", func(t *testing.T) {
		invalidLabels := types.AgentLabels{
			"valid-key": "invalid@value", // Value contains @ which is not allowed
		}

		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "test-host",
			Version:   "1.0.0",
			IP:        "192.168.1.2", // Add required IP field
			MachineID: "test-machine-id",
			Labels:    invalidLabels,
			Kind:      types.AgentKindGithub,
			GithubContext: &types.GitHubContext{
				Job:      "test-job",
				RunID:    "12345",
				Workflow: "test-workflow",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid label value format")
	})

	// Test label key too long
	t.Run("label key too long", func(t *testing.T) {
		longKey := ""
		for i := 0; i < types.MaxLabelKeyLength+1; i++ { //nolint:intrange
			longKey += "a"
		}

		invalidLabels := types.AgentLabels{
			longKey: "value",
		}

		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "test-host",
			Version:   "1.0.0",
			IP:        "192.168.1.3", // Add required IP field
			MachineID: "test-machine-id",
			Labels:    invalidLabels,
			Kind:      types.AgentKindGithub,
			GithubContext: &types.GitHubContext{
				Job:      "test-job",
				RunID:    "12345",
				Workflow: "test-workflow",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "label key exceeds maximum length")
	})

	// Test label value too long
	t.Run("label value too long", func(t *testing.T) {
		longValue := ""
		for i := 0; i < types.MaxLabelValueLength+1; i++ { //nolint:intrange
			longValue += "a"
		}

		invalidLabels := types.AgentLabels{
			"key": longValue,
		}

		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "test-host",
			Version:   "1.0.0",
			IP:        "192.168.1.4", // Add required IP field
			MachineID: "test-machine-id",
			Labels:    invalidLabels,
			Kind:      types.AgentKindGithub,
			GithubContext: &types.GitHubContext{
				Job:      "test-job",
				RunID:    "12345",
				Workflow: "test-workflow",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "label value exceeds maximum length")
	})

	// Test too many labels
	t.Run("too many labels", func(t *testing.T) {
		tooManyLabels := make(types.AgentLabels)
		for i := range types.MaxLabelsCount + 1 {
			tooManyLabels[fmt.Sprintf("label%d", i)] = "value"
		}

		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "test-host",
			Version:   "1.0.0",
			IP:        "192.168.1.5", // Add required IP field
			MachineID: "test-machine-id",
			Labels:    tooManyLabels,
			Kind:      types.AgentKindGithub,
			GithubContext: &types.GitHubContext{
				Job:      "test-job",
				RunID:    "12345",
				Workflow: "test-workflow",
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many labels")
	})

	// Agent update doesn't support updating labels

	// Test listing agents by label filters
	t.Run("list agents by label", func(t *testing.T) {
		// Create agents with different labels
		setupAgent(ctx, t, client,
			WithLabels(types.AgentLabels{"filter-test": "value1", "common": "shared"}),
		)

		setupAgent(ctx, t, client,
			WithLabels(types.AgentLabels{"filter-test": "value2", "common": "shared"}),
		)

		// Filter by exact match
		resp1, err := client.Agents(ctx, types.ListAgents{
			Labels: types.AgentLabels{
				"filter-test": "value1",
			},
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp1.Items), 1)

		// Verify filter worked
		for _, agent := range resp1.Items {
			if val, ok := agent.Labels["filter-test"]; ok {
				assert.Equal(t, "value1", val)
			}
		}

		// Filter by another label
		resp2, err := client.Agents(ctx, types.ListAgents{
			Labels: types.AgentLabels{
				"common": "shared",
			},
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp2.Items), 2)

		// Verify both agents with common label are included
		var foundValue1, foundValue2 bool
		for _, agent := range resp2.Items {
			if val, ok := agent.Labels["filter-test"]; ok {
				if val == "value1" {
					foundValue1 = true
				}
				if val == "value2" {
					foundValue2 = true
				}
			}
		}
		assert.True(t, foundValue1, "Should find agent with filter-test=value1")
		assert.True(t, foundValue2, "Should find agent with filter-test=value2")
	})
}

func TestUpdateFromVanillaToGithub(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// create a vanilla agent
	created, err := client.CreateAgent(ctx, types.CreateAgent{
		ProjectID: "1234",
		OS:        "linux",
		Arch:      "amd64",
		Hostname:  "jenkins",
		Version:   "1.0.0",
		IP:        "192.168.0.1",
		MachineID: "1234",
		Labels:    types.AgentLabels{},
		Kind:      "vanilla",
		VanillaContext: &types.AgentVanillaContext{
			Job:       "test-job",
			RunnerOS:  "linux",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	})

	require.NoError(t, err, "Failed to create vanilla agent")

	k := types.AgentKindGithub
	// update saying we want to change it to github
	err = client.UpdateAgent(ctx, created.ID, types.UpdateAgent{
		Kind: &k,
		GithubContext: &types.GitHubContext{
			Action:            "test-action",
			Actor:             "test-user",
			ActorID:           "12345",
			EventName:         "pull_request",
			Job:               "run", // Required field
			Ref:               "refs/pull/123/merge",
			RefName:           "123/merge",
			RefProtected:      false,
			RefType:           "branch",
			Repository:        "listendev/jibril",
			RepositoryID:      "12345678",
			RepositoryOwner:   "listendev",
			RepositoryOwnerID: "87654321",
			RunAttempt:        "1",
			RunID:             "12345678901", // Required field
			RunNumber:         "100",
			RunnerArch:        "X64",
			RunnerOS:          "Linux",
			ServerURL:         "https://github.com",
			SHA:               "0123456789abcdef0123456789abcdef01234567",
			TriggeringActor:   "test-user",
			Workflow:          "Test Workflow", // Required field
			WorkflowRef:       "listendev/jibril/.github/workflows/test.yaml@refs/pull/123/merge",
			WorkflowSHA:       "0123456789abcdef0123456789abcdef01234567",
			Workspace:         "/home/runner/work/jibril/jibril",
		},
	})

	require.NoError(t, err, "Failed to update agent to github")

	// verify the agent was updated
	agent, err := client.Agent(ctx, created.ID)
	require.NoError(t, err, "Failed to get agent after update")

	require.Equal(t, "github", agent.Kind.String(), "Expected agent kind to be github")
	require.NotNil(t, agent.GithubContext, "Expected github context to be set")
}
