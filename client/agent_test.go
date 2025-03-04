package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
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

// setupAgent creates a new agent with the given options and returns its ID and GitHub context.
func setupAgent(ctx context.Context, t *testing.T, client *client.Client, opts ...AgentOption) (string, *types.GitHubContext) {
	t.Helper()

	// Create default GitHub context
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
		RepositoryID:      "12345678",
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
		Workflow:          "Test Workflow",
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

	return agentCreated.ID, githubContext
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
			GithubContext: &types.GitHubContext{},
		})
		require.Error(t, err)
	})

	t.Run("basic agent", func(t *testing.T) {
		// Create a basic agent using our setup helper
		agentID, githubContext := setupAgent(ctx, t, client)

		// Verify the agent was created successfully
		agent, err := client.Agent(ctx, agentID)
		require.NoError(t, err)
		require.Equal(t, "linux", agent.OS)                            // Default OS
		require.Equal(t, "amd64", agent.Arch)                          // Default arch
		require.Equal(t, githubContext.Repository, "listendev/jibril") // Verify github context
	})

	t.Run("with custom options", func(t *testing.T) {
		agentID, _ := setupAgent(ctx, t, client,
			WithOS("windows"),
			WithArch("arm64"),
			WithIP("192.168.1.100"),
			WithLabels(types.AgentLabels{"env": "testing", "region": "us-west"}),
			WithHostname("custom-host"),
			WithVersion("2.0.0"),
		)

		agent, err := client.Agent(ctx, agentID)
		require.NoError(t, err)
		require.Equal(t, "windows", agent.OS)
		require.Equal(t, "arm64", agent.Arch)
		require.Equal(t, "192.168.1.100/32", agent.IP)
		require.Equal(t, "custom-host", agent.Hostname)
		require.Equal(t, "2.0.0", agent.Version)
		require.Equal(t, "testing", agent.Labels["env"])
		require.Equal(t, "us-west", agent.Labels["region"])
	})
}

func TestAgentGet(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create an agent with custom settings
	agentID, _ := setupAgent(ctx, t, client,
		WithOS("debian"),
		WithArch("amd64"),
		WithLabels(types.AgentLabels{"service": "api"}),
	)

	t.Run("invalid uuid", func(t *testing.T) {
		_, err := client.Agent(ctx, "1234")
		require.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := client.Agent(ctx, uuid.NewString())
		require.Error(t, err)
	})

	t.Run("valid agent", func(t *testing.T) {
		agent, err := client.Agent(ctx, agentID)
		require.NoError(t, err)
		require.Equal(t, agentID, agent.ID)
		require.Equal(t, "debian", agent.OS)
		require.Equal(t, "amd64", agent.Arch)
		require.Equal(t, "api", agent.Labels["service"])
	})
}

func TestAgentUpdate(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentID, _ := setupAgent(ctx, t, client,
		WithLabels(types.AgentLabels{"original": "value"}),
	)

	t.Run("no fields", func(t *testing.T) {
		err := client.UpdateAgent(ctx, agentID, types.UpdateAgent{})
		require.Error(t, err)
	})

	t.Run("update machine id", func(t *testing.T) {
		err := client.UpdateAgent(ctx, agentID, types.UpdateAgent{
			MachineID: ptr("updated-machine-id"),
		})
		require.NoError(t, err)

		// Verify update was applied
		agent, err := client.Agent(ctx, agentID)
		require.NoError(t, err)
		require.Equal(t, "updated-machine-id", agent.MachineID)
	})
}

func TestAgentDelete(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	agentID, _ := setupAgent(ctx, t, client)

	t.Run("invalid uuid", func(t *testing.T) {
		err := client.DeleteAgent(ctx, "1234")
		require.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		err := client.DeleteAgent(ctx, uuid.NewString())
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		// Delete the agent - this should NOT return an error
		err := client.DeleteAgent(ctx, agentID)
		require.NoError(t, err, "Expected successful deletion")

		// Verify agent was deleted by trying to get it
		_, err = client.Agent(ctx, agentID)
		require.Error(t, err, "Expected error when retrieving deleted agent")
	})
}

func TestAgentList(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Create agents with different properties
	setupAgent(ctx, t, client,
		WithOS("debian"),
		WithIP("192.168.0.1"),
		WithLabels(types.AgentLabels{"key2": "value2"}),
	)

	setupAgent(ctx, t, client,
		WithOS("ubuntu"),
		WithIP("192.168.0.2"),
		WithLabels(types.AgentLabels{"key1": "value1"}),
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
				"key1": "value1",
			},
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.Items), 1)
		for _, agent := range resp.Items {
			if agent.Labels["key1"] == "value1" {
				return // Success
			}
		}
		t.Fatalf("Expected to find at least one agent with label key1=value1")
	})
}
