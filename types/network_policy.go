package types

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/listendev/jibril-server/types/errs"
)

// Network policy error constants.
const (
	ErrInvalidNetworkPolicyScope         = errs.InvalidArgumentError("invalid network policy scope")
	ErrInvalidNetworkPolicyRepositoryID  = errs.InvalidArgumentError("invalid network policy repository id")
	ErrInvalidNetworkPolicyWorkflowName  = errs.InvalidArgumentError("invalid network policy workflow name")
	ErrInvalidNetworkPolicyRuleType      = errs.InvalidArgumentError("invalid network policy rule type")
	ErrInvalidNetworkPolicyRuleValue     = errs.InvalidArgumentError("invalid network policy rule value")
	ErrInvalidNetworkPolicyCIDRMode      = errs.InvalidArgumentError("invalid network policy CIDR mode")
	ErrInvalidNetworkPolicyCIDRPolicy    = errs.InvalidArgumentError("invalid network policy CIDR policy")
	ErrInvalidNetworkPolicyResolveMode   = errs.InvalidArgumentError("invalid network policy resolve mode")
	ErrInvalidNetworkPolicyResolvePolicy = errs.InvalidArgumentError("invalid network policy resolve policy")
	ErrNetworkPolicyUnauthorized         = errs.UnauthorizedError("permission denied")
	ErrNetworkPolicyNotFound             = errs.NotFoundError("network policy not found")
	ErrNetworkPolicyRuleNotFound         = errs.NotFoundError("network policy rule not found")
	ErrNetworkPolicyAlreadyExists        = errs.ConflictError("network policy already exists")
	ErrNetworkPolicyRuleAlreadyExists    = errs.ConflictError("network policy rule already exists")
)

// NetworkPolicyScope represents the possible scopes of a network policy.
type NetworkPolicyScope string

const (
	NetworkPolicyScopeGlobal   NetworkPolicyScope = "global"
	NetworkPolicyScopeRepo     NetworkPolicyScope = "repo"
	NetworkPolicyScopeWorkflow NetworkPolicyScope = "workflow"
)

// String returns the string representation of the NetworkPolicyScope.
func (s NetworkPolicyScope) String() string {
	return string(s)
}

// IsValid checks if the NetworkPolicyScope is valid.
func (s NetworkPolicyScope) IsValid() bool {
	switch s {
	case NetworkPolicyScopeGlobal, NetworkPolicyScopeRepo, NetworkPolicyScopeWorkflow:
		return true
	}
	return false
}

// NetworkPolicyCIDRMode represents the possible modes for CIDR handling.
type NetworkPolicyCIDRMode string

const (
	NetworkPolicyCIDRModeIPv4 NetworkPolicyCIDRMode = "ipv4"
	NetworkPolicyCIDRModeIPv6 NetworkPolicyCIDRMode = "ipv6"
	NetworkPolicyCIDRModeBoth NetworkPolicyCIDRMode = "both"
)

// String returns the string representation of the NetworkPolicyCIDRMode.
func (m NetworkPolicyCIDRMode) String() string {
	return string(m)
}

// IsValid checks if the NetworkPolicyCIDRMode is valid.
func (m NetworkPolicyCIDRMode) IsValid() bool {
	switch m {
	case NetworkPolicyCIDRModeIPv4, NetworkPolicyCIDRModeIPv6, NetworkPolicyCIDRModeBoth:
		return true
	}
	return false
}

// NetworkPolicyType represents the possible policy types.
type NetworkPolicyType string

const (
	NetworkPolicyTypeAllow NetworkPolicyType = "allow"
	NetworkPolicyTypeDeny  NetworkPolicyType = "deny"
)

// String returns the string representation of the NetworkPolicyType.
func (p NetworkPolicyType) String() string {
	return string(p)
}

// IsValid checks if the NetworkPolicyType is valid.
func (p NetworkPolicyType) IsValid() bool {
	switch p {
	case NetworkPolicyTypeAllow, NetworkPolicyTypeDeny:
		return true
	}
	return false
}

// NetworkPolicyResolveMode represents the possible modes for DNS resolution.
type NetworkPolicyResolveMode string

const (
	NetworkPolicyResolveModsBypass     NetworkPolicyResolveMode = "bypass"
	NetworkPolicyResolveModeStrict     NetworkPolicyResolveMode = "strict"
	NetworkPolicyResolveModePermissive NetworkPolicyResolveMode = "permissive"
)

// String returns the string representation of the NetworkPolicyResolveMode.
func (m NetworkPolicyResolveMode) String() string {
	return string(m)
}

// IsValid checks if the NetworkPolicyResolveMode is valid.
func (m NetworkPolicyResolveMode) IsValid() bool {
	switch m {
	case NetworkPolicyResolveModsBypass, NetworkPolicyResolveModeStrict, NetworkPolicyResolveModePermissive:
		return true
	}
	return false
}

// NetworkPolicyRuleType represents the type of network policy rule.
type NetworkPolicyRuleType string

const (
	NetworkPolicyRuleTypeCIDR   NetworkPolicyRuleType = "cidr"
	NetworkPolicyRuleTypeDomain NetworkPolicyRuleType = "domain"
)

// String returns the string representation of the NetworkPolicyRuleType.
func (t NetworkPolicyRuleType) String() string {
	return string(t)
}

// IsValid checks if the NetworkPolicyRuleType is valid.
func (t NetworkPolicyRuleType) IsValid() bool {
	switch t {
	case NetworkPolicyRuleTypeCIDR, NetworkPolicyRuleTypeDomain:
		return true
	}
	return false
}

// NetworkPolicyRule represents a single rule in a network policy.
type NetworkPolicyRule struct {
	ID        string                `json:"id"`
	PolicyID  string                `json:"policy_id"`
	Type      NetworkPolicyRuleType `json:"type"`
	Value     string                `json:"value"`
	Action    NetworkPolicyType     `json:"action"`
	CreatedAt time.Time             `json:"created_at"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// Validate ensures the NetworkPolicyRule is valid.
func (r *NetworkPolicyRule) Validate() error {
	// Validate rule type
	if !r.Type.IsValid() {
		return ErrInvalidNetworkPolicyRuleType
	}

	// Validate action
	if !r.Action.IsValid() {
		return ErrInvalidNetworkPolicyCIDRPolicy
	}

	// Validate rule value based on type
	if r.Type == NetworkPolicyRuleTypeCIDR {
		_, _, err := net.ParseCIDR(r.Value)
		if err != nil {
			return ErrInvalidNetworkPolicyRuleValue
		}
	} else if r.Type == NetworkPolicyRuleTypeDomain {
		if r.Value == "" {
			return ErrInvalidNetworkPolicyRuleValue
		}
		// Could add more sophisticated domain validation here
	}

	return nil
}

// NetworkPolicyConfig represents the configuration options for a network policy.
type NetworkPolicyConfig struct {
	CIDRMode      NetworkPolicyCIDRMode    `json:"cidr_mode"`
	CIDRPolicy    NetworkPolicyType        `json:"cidr_policy"`
	ResolveMode   NetworkPolicyResolveMode `json:"resolve_mode"`
	ResolvePolicy NetworkPolicyType        `json:"resolve_policy"`
}

// Validate ensures the NetworkPolicyConfig is valid.
func (c *NetworkPolicyConfig) Validate() error {
	// Validate CIDR mode
	if !c.CIDRMode.IsValid() {
		return ErrInvalidNetworkPolicyCIDRMode
	}

	// Validate CIDR policy
	if !c.CIDRPolicy.IsValid() {
		return ErrInvalidNetworkPolicyCIDRPolicy
	}

	// Validate resolve mode
	if !c.ResolveMode.IsValid() {
		return ErrInvalidNetworkPolicyResolveMode
	}

	// Validate resolve policy
	if !c.ResolvePolicy.IsValid() {
		return ErrInvalidNetworkPolicyResolvePolicy
	}

	return nil
}

// Scan implements the sql.Scanner interface for NetworkPolicyConfig.
func (c *NetworkPolicyConfig) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, c)
	case string:
		return json.Unmarshal([]byte(v), c)
	default:
		return fmt.Errorf("unsupported type for NetworkPolicyConfig: %T", value)
	}
}

// NetworkPolicy represents the base network policy model.
type NetworkPolicy struct {
	ID        string              `json:"id"`
	ProjectID string              `json:"-"` // Not exposed in API
	Scope     NetworkPolicyScope  `json:"scope"`
	Config    NetworkPolicyConfig `json:"config"`
	Rules     []NetworkPolicyRule `json:"rules"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
	DeletedAt *time.Time          `json:"deleted_at,omitempty"`
}

// GlobalNetworkPolicy represents a network policy with global scope.
type GlobalNetworkPolicy struct {
	NetworkPolicy
}

// RepoNetworkPolicy represents a network policy with repository scope.
type RepoNetworkPolicy struct {
	NetworkPolicy
	RepositoryID string `json:"repository_id"`
}

// WorkflowNetworkPolicy represents a network policy with workflow scope.
type WorkflowNetworkPolicy struct {
	NetworkPolicy
	RepositoryID string `json:"repository_id"`
	WorkflowName string `json:"workflow_name"`
}

// MergedNetworkPolicy represents a network policy that combines all applicable policies.
type MergedNetworkPolicy struct {
	Config         NetworkPolicyConfig    `json:"config"`
	Rules          []NetworkPolicyRule    `json:"rules"`
	GlobalPolicy   *NetworkPolicy         `json:"global_policy,omitempty"`
	RepoPolicy     *RepoNetworkPolicy     `json:"repo_policy,omitempty"`
	WorkflowPolicy *WorkflowNetworkPolicy `json:"workflow_policy,omitempty"`
}

// CreateNetworkPolicy represents the request to create a new network policy.
type CreateNetworkPolicy struct {
	Scope        NetworkPolicyScope        `json:"scope"`
	Config       NetworkPolicyConfig       `json:"config"`
	Rules        []CreateNetworkPolicyRule `json:"rules,omitempty"`
	RepositoryID string                    `json:"repository_id,omitempty"`
	WorkflowName string                    `json:"workflow_name,omitempty"`
	ProjectID    string                    `json:"-"` // Populated by the service layer, not exposed in API
}

// Validate ensures the CreateNetworkPolicy request is valid.
func (c *CreateNetworkPolicy) Validate() error {
	// Check network policy scope
	if !c.Scope.IsValid() {
		return ErrInvalidNetworkPolicyScope
	}

	// Validate required fields based on scope
	if c.Scope == NetworkPolicyScopeRepo && c.RepositoryID == "" {
		return ErrInvalidNetworkPolicyRepositoryID
	}

	if c.Scope == NetworkPolicyScopeWorkflow {
		if c.RepositoryID == "" {
			return ErrInvalidNetworkPolicyRepositoryID
		}
		if c.WorkflowName == "" {
			return ErrInvalidNetworkPolicyWorkflowName
		}
	}

	// Validate config
	if err := c.Config.Validate(); err != nil {
		return err
	}

	// Validate rules if provided
	for _, rule := range c.Rules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// NetworkPolicyCreated represents the response when a network policy is successfully created.
type NetworkPolicyCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateNetworkPolicy represents the request to update an existing network policy.
type UpdateNetworkPolicy struct {
	Config *NetworkPolicyConfig `json:"config"`
}

// Validate ensures the UpdateNetworkPolicy request is valid.
func (u *UpdateNetworkPolicy) Validate() error {
	// Config is required
	if u.Config == nil {
		return errs.InvalidArgumentError("config is required")
	}

	// Validate config
	if err := u.Config.Validate(); err != nil {
		return err
	}

	return nil
}

// NetworkPolicyUpdated represents the response when a network policy is successfully updated.
type NetworkPolicyUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateNetworkPolicyRule represents the request to create a new network policy rule.
// The PolicyID is populated by the service layer.
type CreateNetworkPolicyRule struct {
	Type   NetworkPolicyRuleType `json:"type"`
	Value  string                `json:"value"`
	Action NetworkPolicyType     `json:"action"`
}

// Validate ensures the CreateNetworkPolicyRule request is valid.
func (c *CreateNetworkPolicyRule) Validate() error {
	// Create a temporary rule to validate the type and value
	rule := NetworkPolicyRule{
		Type:   c.Type,
		Value:  c.Value,
		Action: c.Action,
	}

	return rule.Validate()
}

// NetworkPolicyRuleCreated represents the response when a network policy rule is successfully created.
type NetworkPolicyRuleCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// UpdateNetworkPolicyRule represents the request to update an existing network policy rule.
type UpdateNetworkPolicyRule struct {
	Value  *string            `json:"value,omitempty"`
	Action *NetworkPolicyType `json:"action,omitempty"`
}

// Validate ensures the UpdateNetworkPolicyRule request is valid.
func (u *UpdateNetworkPolicyRule) Validate() error {
	// Check if any fields are specified
	if u.Value == nil && u.Action == nil {
		return errs.InvalidArgumentError("at least one field is required")
	}

	// Validate action if provided
	if u.Action != nil && !u.Action.IsValid() {
		return ErrInvalidNetworkPolicyCIDRPolicy
	}

	// Value validation will need to happen in the service layer since we need the rule type

	return nil
}

// NetworkPolicyRuleUpdated represents the response when a network policy rule is successfully updated.
type NetworkPolicyRuleUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GetMergedNetworkPolicy constructs a merged policy from the provided policies.
func GetMergedNetworkPolicy(global *GlobalNetworkPolicy, repo *RepoNetworkPolicy, workflow *WorkflowNetworkPolicy) *MergedNetworkPolicy {
	// Start with a default config
	merged := &MergedNetworkPolicy{
		Config: NetworkPolicyConfig{
			CIDRMode:      NetworkPolicyCIDRModeBoth,      // Default values
			CIDRPolicy:    NetworkPolicyTypeAllow,         // Default values
			ResolveMode:   NetworkPolicyResolveModsBypass, // Default values
			ResolvePolicy: NetworkPolicyTypeAllow,         // Default values
		},
		Rules: []NetworkPolicyRule{},
	}

	// Add global policy if available
	if global != nil {
		merged.GlobalPolicy = &global.NetworkPolicy

		// Track original rules for each policy level
		globalRules := make([]NetworkPolicyRule, len(global.Rules))
		copy(globalRules, global.Rules)
		merged.Rules = append(merged.Rules, globalRules...)

		// Global config overrides the defaults
		merged.Config = global.Config
	}

	// Add repo policy if available (repo overrides global)
	if repo != nil {
		merged.RepoPolicy = repo

		// Add repo rules
		repoRules := make([]NetworkPolicyRule, len(repo.Rules))
		copy(repoRules, repo.Rules)
		merged.Rules = append(merged.Rules, repoRules...)

		// Repo config overrides global config
		merged.Config = repo.Config
	}

	// Add workflow policy if available (workflow overrides repo and global)
	if workflow != nil {
		merged.WorkflowPolicy = workflow

		// Add workflow rules
		workflowRules := make([]NetworkPolicyRule, len(workflow.Rules))
		copy(workflowRules, workflow.Rules)
		merged.Rules = append(merged.Rules, workflowRules...)

		// Workflow config has the highest precedence
		merged.Config = workflow.Config
	}

	return merged
}

// GetDefaultNetworkPolicyConfig returns a default network policy configuration.
func GetDefaultNetworkPolicyConfig() NetworkPolicyConfig {
	return NetworkPolicyConfig{
		CIDRMode:      NetworkPolicyCIDRModeBoth,
		CIDRPolicy:    NetworkPolicyTypeAllow,
		ResolveMode:   NetworkPolicyResolveModsBypass,
		ResolvePolicy: NetworkPolicyTypeAllow,
	}
}

// CreateDefaultRepoNetworkPolicy creates a default CreateNetworkPolicy for a repository.
func CreateDefaultRepoNetworkPolicy(repositoryID string) CreateNetworkPolicy {
	return CreateNetworkPolicy{
		Scope:        NetworkPolicyScopeRepo,
		RepositoryID: repositoryID,
		Config:       GetDefaultNetworkPolicyConfig(),
	}
}

// CreateDefaultWorkflowNetworkPolicy creates a default CreateNetworkPolicy for a workflow.
func CreateDefaultWorkflowNetworkPolicy(repositoryID, workflowName string) CreateNetworkPolicy {
	return CreateNetworkPolicy{
		Scope:        NetworkPolicyScopeWorkflow,
		RepositoryID: repositoryID,
		WorkflowName: workflowName,
		Config:       GetDefaultNetworkPolicyConfig(),
	}
}
