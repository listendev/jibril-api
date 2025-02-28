package client_test

import (
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
)

func TestAgent(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("create with empty payload", func(t *testing.T) {
		_, err := client.CreateAgent(ctx, types.CreateAgent{})
		require.Error(t, err)
	})

	t.Run("create with invalid payload", func(t *testing.T) {
		_, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:            "linux",
			Arch:          "amd64",
			Hostname:      "jenkins",
			Version:       "1.0.0",
			IP:            "192.168.0.1",
			MachineID:     "1234",
			Labels:        types.AgentLabels{},
			Kind:          "invalid",
			GithubContext: &types.GitHubContext{},
		})
		require.Error(t, err)
	})

	var agentID string

	githubContext := &types.GitHubContext{
		Action:            "13. Access bad domain (pornhub)",
		Actor:             "rafaeldtinoco",
		ActorID:           "7395852",
		EventName:         "pull_request",
		Job:               "run",
		Ref:               "refs/pull/373/merge",
		RefName:           "373/merge",
		RefProtected:      false,
		RefType:           "branch",
		Repository:        "listendev/jibril",
		RepositoryID:      "785073365",
		RepositoryOwner:   "listendev",
		RepositoryOwnerID: "103680976",
		RunAttempt:        "1",
		RunID:             "13171784858",
		RunNumber:         "200",
		RunnerArch:        "X64",
		RunnerOS:          "Linux",
		ServerURL:         "https://github.com",
		SHA:               "27bca8119f027a906e72c8ff94eb60bb1fea78fb",
		TriggeringActor:   "rafaeldtinoco",
		Workflow:          "Build and Run Tests",
		WorkflowRef:       "listendev/jibril/.github/workflows/build-and-run-tests.yaml@refs/pull/373/merge",
		WorkflowSHA:       "27bca8119f027a906e72c8ff94eb60bb1fea78fb",
		Workspace:         "/home/runner/work/jibril/jibril",
	}

	t.Run("create", func(t *testing.T) {
		agentCreated, err := client.CreateAgent(ctx, types.CreateAgent{
			OS:            "linux",
			Arch:          "amd64",
			Hostname:      "jenkins",
			Version:       "1.0.0",
			IP:            "192.168.0.1",
			MachineID:     "1234",
			Labels:        types.AgentLabels{},
			Kind:          types.AgentKindGithub,
			GithubContext: githubContext,
		})

		require.NoError(t, err, "expected no error when creating an agent")
		require.NotEmpty(t, agentCreated.ID, "expected a valid agent ID to be returned")
		require.NotEmpty(t, agentCreated.AgentToken)

		agentID = agentCreated.ID
	})

	t.Run("get agent with invalid uuid", func(t *testing.T) {
		_, err := client.Agent(ctx, "1234")
		require.Error(t, err)
	})

	t.Run("get", func(t *testing.T) {
		agentGot, err := client.Agent(ctx, agentID)
		require.NoError(t, err)
		require.Equal(t, agentID, agentGot.ID)
	})

	t.Run("update with no field supplied", func(t *testing.T) {
		err := client.UpdateAgent(ctx, agentID, types.UpdateAgent{})
		require.Error(t, err)
	})

	t.Run("update machine id", func(t *testing.T) {
		err := client.UpdateAgent(ctx, agentID, types.UpdateAgent{
			MachineID: ptr("5678"),
		})
		require.NoError(t, err)
	})

	t.Run("delete invalid uuid", func(t *testing.T) {
		err := client.DeleteAgent(ctx, "1234")
		require.Error(t, err)
	})

	t.Run("delete agent not found", func(t *testing.T) {
		random := uuid.NewString()
		err := client.DeleteAgent(ctx, random)
		require.Error(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		err := client.DeleteAgent(ctx, agentID)
		require.NoError(t, err)
	})

	a1, err := client.CreateAgent(ctx, types.CreateAgent{
		OS:        "debian",
		Arch:      "amd64",
		Hostname:  "jenkins",
		Version:   "1.0.0",
		IP:        "192.168.0.1",
		MachineID: "1234",
		Labels: types.AgentLabels{
			"key2": "value2",
		},
		Kind:          types.AgentKindGithub,
		GithubContext: githubContext,
	})
	require.NoError(t, err)

	a2, err := client.CreateAgent(ctx, types.CreateAgent{
		OS:        "ubuntu",
		Arch:      "amd64",
		Hostname:  "jenkins",
		Version:   "1.0.0",
		IP:        "192.168.0.2",
		MachineID: "5678",
		Labels: types.AgentLabels{
			"key1": "value1",
		},
		Kind:          types.AgentKindGithub,
		GithubContext: githubContext,
	})
	require.NoError(t, err)

	_ = a1
	_ = a2

	t.Run("empty filter return everything", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{})
		require.NoError(t, err)
		require.Len(t, resp.Items, 2)
		require.False(t, resp.PageInfo.HasNextPage)
		require.False(t, resp.PageInfo.HasPrevPage)
		require.NotNil(t, resp.PageInfo.StartCursor)
		require.NotNil(t, resp.PageInfo.EndCursor)
	})

	t.Run("filter by os", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{
			Filters: &types.AgentFilters{OS: ptr("ubuntu")},
		})
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)
		require.False(t, resp.PageInfo.HasNextPage)
		require.False(t, resp.PageInfo.HasPrevPage)
		require.NotNil(t, resp.PageInfo.StartCursor)
		require.NotNil(t, resp.PageInfo.EndCursor)
	})

	t.Run("filter by ip", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{
			Filters: &types.AgentFilters{IP: ptr("192.168.0.1")},
		})
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)
		require.False(t, resp.PageInfo.HasNextPage)
		require.False(t, resp.PageInfo.HasPrevPage)
		require.NotNil(t, resp.PageInfo.StartCursor)
		require.NotNil(t, resp.PageInfo.EndCursor)
	})

	t.Run("filter by labels metadata", func(t *testing.T) {
		resp, err := client.Agents(ctx, types.ListAgents{
			Labels: types.AgentLabels{
				"key1": "value1",
			},
		})
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)
		require.False(t, resp.PageInfo.HasNextPage)
		require.False(t, resp.PageInfo.HasPrevPage)
		require.NotNil(t, resp.PageInfo.StartCursor)
		require.NotNil(t, resp.PageInfo.EndCursor)

		resp, err = client.Agents(ctx, types.ListAgents{
			Labels: types.AgentLabels{
				"key1": "value1",
			},
			PageArgs: types.PageArgs{
				After: resp.PageInfo.EndCursor,
			},
		})

		require.NoError(t, err)
		require.Len(t, resp.Items, 0)
	})
}
