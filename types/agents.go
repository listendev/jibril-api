package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type AgentKind string

const (
	AgentKindGithub     AgentKind = "github"
	AgentKindKubernetes AgentKind = "kubernetes"
)

func (k AgentKind) String() string {
	return string(k)
}

func (k AgentKind) IsValid() bool {
	switch k {
	case AgentKindGithub, AgentKindKubernetes:
		return true
	}

	return false
}

// AgentLabels represents a typed map of labels.
type AgentLabels map[string]string

// UnmarshalJSON implements custom JSON unmarshaling for AgentLabels.
func (l *AgentLabels) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*l = make(AgentLabels)

		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	*l = m

	return nil
}

// Scan implements sql.Scanner interface.
func (l *AgentLabels) Scan(value interface{}) error {
	if value == nil {
		*l = make(AgentLabels)

		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, l)
	case string:
		return json.Unmarshal([]byte(v), l)
	default:
		return fmt.Errorf("unsupported type for AgentLabels: %T", value)
	}
}

// AgentGithubContext represents GitHub-specific context.
type AgentGithubContext struct {
	Repository     string `json:"repository"`
	Owner          string `json:"owner"`
	InstallationID int64  `json:"installation_id"`
	// Extra fields
}

func (c *AgentGithubContext) Validate() error {
	if c == nil {
		return errors.New("github context is required")
	}

	var errs []string
	if c.Repository == "" {
		errs = append(errs, "repository is required")
	}

	if c.Owner == "" {
		errs = append(errs, "owner is required")
	}

	if c.InstallationID == 0 {
		errs = append(errs, "installation_id is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid github context: %s", join(errs, ", "))
	}

	return nil
}

// AgentKubernetesContext represents Kubernetes-specific context.
type AgentKubernetesContext struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
}

func (c *AgentKubernetesContext) Validate() error {
	if c == nil {
		return errors.New("kubernetes context is required")
	}

	var errs []string
	if c.Cluster == "" {
		errs = append(errs, "cluster is required")
	}

	if c.Namespace == "" {
		errs = append(errs, "namespace is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid kubernetes context: %s", join(errs, ", "))
	}

	return nil
}

// Agent represents the stored agent model.
type Agent struct {
	ID                string                  `db:"id"         json:"id"`
	OS                string                  `db:"os"         json:"os"`
	Arch              string                  `db:"arch"       json:"arch"`
	Hostname          string                  `db:"hostname"   json:"hostname"`
	Version           string                  `db:"version"    json:"version"`
	IP                string                  `db:"ip"         json:"ip"`
	MachineID         string                  `db:"machine_id" json:"machine_id"`
	Labels            AgentLabels             `db:"labels"     json:"labels"`
	Kind              AgentKind               `db:"kind"       json:"kind"`
	GithubContext     *AgentGithubContext     `db:"-"          json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `db:"-"          json:"kubernetes_context,omitempty"`
	Active            bool                    `db:"active"     json:"active"`
	CreatedAt         time.Time               `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time               `db:"updated_at" json:"updated_at"`
}

// CreateAgent represents the request to create a new agent.
type CreateAgent struct {
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	Hostname  string      `json:"hostname"`
	Version   string      `json:"version"`
	IP        string      `json:"ip"`
	MachineID string      `json:"machine_id"`
	Labels    AgentLabels `json:"labels"`
	Kind      AgentKind   `json:"kind"`

	GithubContext     *AgentGithubContext     `json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `json:"kubernetes_context,omitempty"`
}

func (c *CreateAgent) Validate() error {
	if !c.Kind.IsValid() {
		return errors.New("invalid agent kind")
	}

	var errs []string
	if c.OS == "" {
		errs = append(errs, "os is required")
	}

	if c.Arch == "" {
		errs = append(errs, "arch is required")
	}

	if c.Hostname == "" {
		errs = append(errs, "hostname is required")
	}

	if c.Version == "" {
		errs = append(errs, "version is required")
	}

	if c.IP == "" {
		errs = append(errs, "ip is required")
	}

	if c.MachineID == "" {
		errs = append(errs, "machine_id is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid agent: %s", join(errs, ", "))
	}

	// Validate context based on Kind
	switch c.Kind {
	case AgentKindGithub:
		return c.GithubContext.Validate()
	case AgentKindKubernetes:
		return c.KubernetesContext.Validate()
	}

	return nil
}

// UpdateAgent represents the request to update an existing agent.
type UpdateAgent struct {
	OS       *string      `json:"os,omitempty"`
	Arch     *string      `json:"arch,omitempty"`
	Hostname *string      `json:"hostname,omitempty"`
	Version  *string      `json:"version,omitempty"`
	IP       *string      `json:"ip,omitempty"`
	Labels   *AgentLabels `json:"labels,omitempty"`
	Active   *bool        `json:"active,omitempty"`

	GithubContext     *AgentGithubContext     `json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `json:"kubernetes_context,omitempty"`
}

// Helper function to join error messages.
func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}

	if len(strs) == 1 {
		return strs[0]
	}

	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}

	return result
}
