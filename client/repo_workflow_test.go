package client_test

import (
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/assert"
)

// TestRepositoryAndWorkflowFilters tests the repository and workflow filtering functionality.
func TestRepositoryAndWorkflowFilters(t *testing.T) {
	ctx := t.Context()
	client := testclient.WithToken(t)

	// Setup GitHub agent with context
	agentCreated, githubContext := setupAgent(ctx, t, client, WithAgentKind(types.AgentKindGithub))

	// Get repository and workflow values from the first agent
	firstRepoID := githubContext.RepositoryID
	firstRepoName := githubContext.Repository
	firstWorkflow := githubContext.Workflow

	// Create a second GitHub agent with different repo and workflow values
	secondContext := &types.GitHubContext{
		Job:          "test-job-2",
		RunID:        "run-id-2",
		Repository:   "second-repo",
		RepositoryID: "repo-id-2",
		Workflow:     "second-workflow",
	}

	secondAgent := types.CreateAgent{
		OS:            "linux",
		Arch:          "amd64",
		Hostname:      "test-host2",
		Version:       "v1.0.0",
		IP:            "127.0.0.2",
		MachineID:     "machine-id-2-" + uuid.New().String(),
		Kind:          types.AgentKindGithub,
		GithubContext: secondContext,
	}

	secondAgentCreated, err := client.CreateAgent(ctx, secondAgent)
	require.NoError(t, err)

	// Create a third GitHub agent with the same repo as first but different workflow
	thirdContext := &types.GitHubContext{
		Job:          "test-job-3",
		RunID:        "run-id-3",
		Repository:   firstRepoName,
		RepositoryID: firstRepoID,
		Workflow:     "third-workflow",
	}

	thirdAgent := types.CreateAgent{
		OS:            "linux",
		Arch:          "amd64",
		Hostname:      "test-host3",
		Version:       "v1.0.0",
		IP:            "127.0.0.3",
		MachineID:     "machine-id-3-" + uuid.New().String(),
		Kind:          types.AgentKindGithub,
		GithubContext: thirdContext,
	}

	thirdAgentCreated, err := client.CreateAgent(ctx, thirdAgent)
	require.NoError(t, err)

	// Create events with each agent
	_ = setupEvent(ctx, t, client, agentCreated)

	// Create event with second agent
	secondAgentClient := client.WithAgentToken(secondAgentCreated.AgentToken)
	secondEvent := types.CreateOrUpdateEvent{
		ID:      uuid.New().String(),
		AgentID: secondAgentCreated.ID,
		Kind:    types.EventKindFlow,
		Data: types.EventData{
			Process: &types.Process{
				Cmd: ptr("test-cmd-2"),
				PID: ptr(1234),
			},
			Note: ptr("Second test event"),
		},
	}

	secondEventResp, err := secondAgentClient.IngestEvent(ctx, secondEvent)
	require.NoError(t, err)
	_ = secondEventResp // To avoid unused variable warning

	// Create event with third agent
	thirdAgentClient := client.WithAgentToken(thirdAgentCreated.AgentToken)
	thirdEvent := types.CreateOrUpdateEvent{
		ID:      uuid.New().String(),
		AgentID: thirdAgentCreated.ID,
		Kind:    types.EventKindFlow,
		Data: types.EventData{
			Process: &types.Process{
				Cmd: ptr("test-cmd-3"),
				PID: ptr(1234),
			},
			Note: ptr("Third test event"),
		},
	}

	thirdEventResp, err := thirdAgentClient.IngestEvent(ctx, thirdEvent)
	require.NoError(t, err)
	_ = thirdEventResp // To avoid unused variable warning

	// Test filtering by repository ID
	t.Run("filter by repository ID", func(t *testing.T) {
		repoIDFilter := types.ListIssues{
			Filters: &types.IssueFilters{
				RepositoryID: &firstRepoID,
			},
		}
		result, err := client.Issues(ctx, repoIDFilter)
		require.NoError(t, err)

		// Assert we get exactly 2 issues (first and third have the same repo)
		assert.Len(t, result.Items, 2, "Should return exactly 2 issues")
	})

	// Test filtering by repository name
	t.Run("filter by repository name", func(t *testing.T) {
		secondRepoName := "second-repo"
		repoNameFilter := types.ListIssues{
			Filters: &types.IssueFilters{
				Repository: &secondRepoName,
			},
		}
		result, err := client.Issues(ctx, repoNameFilter)
		require.NoError(t, err)

		// Assert we get exactly 1 issue
		assert.Len(t, result.Items, 1, "Should return exactly 1 issue")
	})

	// Test filtering by workflow name
	t.Run("filter by workflow name", func(t *testing.T) {
		workflowFilter := types.ListIssues{
			Filters: &types.IssueFilters{
				WorkflowName: &firstWorkflow,
			},
		}
		result, err := client.Issues(ctx, workflowFilter)
		require.NoError(t, err)

		// Assert we get exactly 1 issue
		assert.Len(t, result.Items, 1, "Should return exactly 1 issue")
	})

	// Test combining repository and workflow filters
	t.Run("combined repository and workflow filters", func(t *testing.T) {
		// Filter for issues from the first repo with the third workflow
		thirdWorkflow := "third-workflow"
		combinedFilter := types.ListIssues{
			Filters: &types.IssueFilters{
				RepositoryID: &firstRepoID,
				WorkflowName: &thirdWorkflow,
			},
		}
		result, err := client.Issues(ctx, combinedFilter)
		require.NoError(t, err)

		// Assert we get exactly 1 issue
		assert.Len(t, result.Items, 1, "Should return exactly 1 issue")
	})

	// Test with non-matching values
	t.Run("non-matching filters", func(t *testing.T) {
		// Use a clearly different repository name than what we set up
		nonExistentRepo := "clearly-non-existent-repository-name-that-wont-match-anything"
		nonMatchingFilter := types.ListIssues{
			Filters: &types.IssueFilters{
				Repository: &nonExistentRepo,
			},
		}

		// Now apply the filter for a non-existent repository
		result, err := client.Issues(ctx, nonMatchingFilter)
		require.NoError(t, err)

		// Assert we get exactly 0 issues for the non-existent repository
		assert.Empty(t, result.Items, "Should return no issues for non-existent repository")
	})
}
