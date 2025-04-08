package client_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectCounters(t *testing.T) {
	ctx := t.Context()

	t.Run("should return zero counts when no agents exist", func(t *testing.T) {
		// Create test environment with a project token
		_, client := testclient.WithProjectTokenForTest(t)

		// Get counters
		counters, err := client.ProjectCounters(ctx)
		require.NoError(t, err)

		// Verify counters are zero since we haven't created any agents
		assert.Equal(t, 0, counters.RepositoryCount)
		assert.Equal(t, 0, counters.WorkflowCount)
	})

	t.Run("should return correct counts with agents", func(t *testing.T) {
		// Create test environment with a project token
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a GitHub agent with a unique repository and workflow
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", "repo1", "repo1-id", "workflow1", "12345", "1"))

		// Create another GitHub agent with the same repository but different workflow
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", "repo1", "repo1-id", "workflow2", "12346", "1"))

		// Create a third GitHub agent with a different repository and same workflow
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", "repo2", "repo2-id", "workflow1", "12347", "1"))

		// Get counters
		counters, err := client.ProjectCounters(ctx)
		require.NoError(t, err)

		// Verify counts are correct: 2 unique repositories and 2 unique workflows
		assert.Equal(t, 2, counters.RepositoryCount)
		assert.Equal(t, 2, counters.WorkflowCount)
	})

	t.Run("should count multiple workflows in the same repository", func(t *testing.T) {
		// Create test environment with a project token
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a unique repository ID for this test
		repoID := "multi-workflow-repo-" + uuid.New().String()[:8]

		// Get counters before our test
		initialCounters, err := client.ProjectCounters(ctx)
		require.NoError(t, err)

		// Create several agents with the same repository but different workflows
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", repoID, repoID, "workflow1", "12350", "1"))
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", repoID, repoID, "workflow2", "12351", "1"))
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", repoID, repoID, "workflow3", "12352", "1"))
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", repoID, repoID, "workflow4", "12353", "1"))
		setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", repoID, repoID, "workflow5", "12354", "1"))

		// Get counters after adding our test agents
		counters, err := client.ProjectCounters(ctx)
		require.NoError(t, err)

		// Verify that we have 1 new repo and 5 new workflows
		assert.Equal(t, initialCounters.RepositoryCount+1, counters.RepositoryCount)
		assert.Equal(t, initialCounters.WorkflowCount+5, counters.WorkflowCount)
	})

	t.Run("should not count deleted agents", func(t *testing.T) {
		// Create test environment with a project token
		_, client := testclient.WithProjectTokenForTest(t)

		// Create a unique identifier for this test
		testID := uuid.New().String()[:8]

		// Create a GitHub agent with a unique repository and workflow
		agentCreated, _ := setupAgent(ctx, t, client,
			WithGitHubContextSimple("owner", "repo-"+testID, "repo-"+testID, "workflow-"+testID, "12345", "1"))

		// Get counters before deletion
		counters, err := client.ProjectCounters(ctx)
		require.NoError(t, err)
		initialRepoCount := counters.RepositoryCount
		initialWorkflowCount := counters.WorkflowCount

		// Delete the agent
		err = client.DeleteAgent(ctx, agentCreated.ID)
		require.NoError(t, err)

		// Get counters after deletion
		counters, err = client.ProjectCounters(ctx)
		require.NoError(t, err)

		// Verify the counts decreased by 1 each (since we deleted an agent with unique repo and workflow)
		assert.Equal(t, initialRepoCount-1, counters.RepositoryCount)
		assert.Equal(t, initialWorkflowCount-1, counters.WorkflowCount)
	})
}
