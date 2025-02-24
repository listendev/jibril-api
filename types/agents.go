package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/listendev/jibril-server/types/errs"
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
		return fmt.Errorf("invalid kubernetes context: %s", join(errs))
	}

	return nil
}

// Agent represents the stored agent model.
type Agent struct {
	ID                string                  `db:"id"         json:"id"`
	ProjectID         string                  `db:"project_id" json:"project_id"`
	OS                string                  `db:"os"         json:"os"`
	Arch              string                  `db:"arch"       json:"arch"`
	Hostname          string                  `db:"hostname"   json:"hostname"`
	Version           string                  `db:"version"    json:"version"`
	IP                string                  `db:"ip"         json:"ip"`
	MachineID         string                  `db:"machine_id" json:"machine_id"`
	Labels            AgentLabels             `db:"labels"     json:"labels"`
	Kind              AgentKind               `db:"kind"       json:"kind"`
	GithubContext     *GitHubContext          `db:"-"          json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `db:"-"          json:"kubernetes_context,omitempty"`
	Active            bool                    `db:"active"     json:"active"`
	CreatedAt         time.Time               `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time               `db:"updated_at" json:"updated_at"`
}

// CreateAgent represents the request to create a new agent.
type CreateAgent struct {
	ProjectID string      `json:"project_id"`
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	Hostname  string      `json:"hostname"`
	Version   string      `json:"version"`
	IP        string      `json:"ip"`
	MachineID string      `json:"machine_id"`
	Labels    AgentLabels `json:"labels"`
	Kind      AgentKind   `json:"kind"`

	GithubContext     *GitHubContext          `json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `json:"kubernetes_context,omitempty"`
}

const (
	ErrInvalidAgentType = errs.InvalidArgumentError("invalid agent kind")
)

func (c *CreateAgent) Validate() error {
	if !c.Kind.IsValid() {
		return ErrInvalidAgentType
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

	ip := net.ParseIP(c.IP)
	if ip == nil {
		errs = append(errs, "invalid ip")
	}

	if c.IP == "" {
		errs = append(errs, "ip is required")
	}

	if c.MachineID == "" {
		errs = append(errs, "machine_id is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid agent: %s", join(errs))
	}

	// Validate context based on Kind
	switch c.Kind {
	case AgentKindGithub:
		return c.GithubContext.Validate()
	case AgentKindKubernetes:
		return c.KubernetesContext.Validate()
	}

	if c.GithubContext == nil && c.KubernetesContext == nil {
		return errors.New("at least one context is required")
	}

	return nil
}

type AgentCreated struct {
	ID         string `json:"id"`
	AgentToken string `json:"agent_token"`
}

// UpdateAgent represents the request to update an existing agent.
type UpdateAgent struct {
	OS        *string `json:"os,omitempty"`
	Arch      *string `json:"arch,omitempty"`
	Hostname  *string `json:"hostname,omitempty"`
	Version   *string `json:"version,omitempty"`
	IP        *string `json:"ip,omitempty"`
	MachineID *string `json:"machine_id,omitempty"`
}

func (a *UpdateAgent) Validate() error {
	if a.OS == nil && a.Arch == nil && a.Hostname == nil && a.Version == nil && a.IP == nil && a.MachineID == nil {
		return errors.New("at least one field is required")
	}

	var errs []string

	if a.OS != nil && *a.OS == "" {
		errs = append(errs, "os valid but empty")
	}

	if a.Arch != nil && *a.Arch == "" {
		errs = append(errs, "arch valid but empty")
	}

	if a.Hostname != nil && *a.Hostname == "" {
		errs = append(errs, "hostname valid but empty")
	}

	if a.Version != nil && *a.Version == "" {
		errs = append(errs, "version valid but empty")
	}

	if a.IP != nil && *a.IP == "" {
		errs = append(errs, "ip valid but empty")
	}

	if a.MachineID != nil && *a.MachineID == "" {
		errs = append(errs, "machine_id valid but empty")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid update agent: %s", join(errs))
	}

	return nil
}

// Helper function to join error messages.
func join(strs []string) string {
	if len(strs) == 0 {
		return ""
	}

	if len(strs) == 1 {
		return strs[0]
	}

	result := strs[0]
	for _, s := range strs[1:] {
		result += "," + s
	}

	return result
}
