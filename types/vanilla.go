package types

import (
	"fmt"
	"time"
)

type AgentVanillaContext struct {
	ID        string    `json:"id"`
	Job       string    `json:"job"`
	RunnerOS  string    `json:"runner_os"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (v *AgentVanillaContext) Validate() error {
	var errs []string

	if v.Job == "" {
		errs = append(errs, "job is required")
	}

	if v.RunnerOS == "" {
		errs = append(errs, "runner_os is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation errors: %v", errs)
	}
	return nil
}
