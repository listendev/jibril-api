package types

import (
	"fmt"
	"time"
)

// AgentGithubContext is the context of the event that happened in the GitHub.
type AgentGithubContext struct {
	ID                string    `json:"id"`
	Action            string    `json:"action"`
	Actor             string    `json:"actor"`
	ActorID           string    `json:"actor_id"`
	EventName         string    `json:"event_name"`
	Job               string    `json:"job"`
	Ref               string    `json:"ref"`
	RefName           string    `json:"ref_name"`
	RefProtected      bool      `json:"ref_protected"`
	RefType           string    `json:"ref_type"`
	Repository        string    `json:"repository"`
	RepositoryID      string    `json:"repository_id"`
	RepositoryOwner   string    `json:"repository_owner"`
	RepositoryOwnerID string    `json:"repository_owner_id"`
	RunAttempt        string    `json:"run_attempt"`
	RunID             string    `json:"run_id"`
	RunNumber         string    `json:"run_number"`
	RunnerArch        string    `json:"runner_arch"`
	RunnerOS          string    `json:"runner_os"`
	ServerURL         string    `json:"server_url"`
	SHA               string    `json:"sha"`
	TriggeringActor   string    `json:"triggering_actor"`
	Workflow          string    `json:"workflow"`
	WorkflowRef       string    `json:"workflow_ref"`
	WorkflowSHA       string    `json:"workflow_sha"`
	Workspace         string    `json:"workspace"`
	CreatedAt         time.Time `json:"created_at"`
	UpdateAt          time.Time `json:"updated_at"`
}

func (g *AgentGithubContext) Validate() error {
	var errs []string

	if g.Job == "" {
		errs = append(errs, "job is required")
	}

	if g.RunID == "" {
		errs = append(errs, "run_id is required")
	}

	if g.Workflow == "" {
		errs = append(errs, "workflow is required")
	}

	// Validate repository information
	if g.Repository == "" {
		errs = append(errs, "repository is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid github context: %s", join(errs))
	}

	return nil
}

// GitHubContext is an alias for AgentGithubContext to maintain backwards compatibility.
// Deprecated: Use AgentGithubContext instead.
type GitHubContext = AgentGithubContext
