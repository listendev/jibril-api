// Package types contains all the required clients for marshal/unmarshal requests and responses from/to jibril-server.
package types

import (
	"time"

	"github.com/listendev/jibril-server/types/errs"
)

const (
	ErrInvalidEventKind = errs.InvalidArgumentError("invalid event kind")
	ErrIDcannotBeEmpty  = errs.InvalidArgumentError("id is required")
)

type EventKind string

const (
	EventKindDropIP     EventKind = "dropip"
	EventKindDropDomain EventKind = "dropdomain"
)

func (k EventKind) OK() bool {
	for _, allowed := range [...]EventKind{
		EventKindDropIP,
		EventKindDropDomain,
	} {
		if k == allowed {
			return true
		}
	}

	return false
}
func (e *Event) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmpty
	}

	if !e.Kind.OK() {
		return ErrInvalidEventKind
	}

	return nil
}

// Event is something that happened in the system.
// Can be of different types but more or less every events has same properties.
type Event struct {
	ID string `json:"id"`
	// projectID is the ID of the listen.dev project.
	projectID string
	// orgID is the ID of the listen.dev organization.
	orgID         string
	Data          EventData      `json:"data"`
	GithubContext *GitHubContext `json:"github_context,omitempty"`
	Kind          EventKind      `json:"kind"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

func (e Event) WithListenDevInfo(projectID, orgID string) Event {
	e.projectID = projectID
	e.orgID = orgID

	return e
}

type EventData struct {
	Dropped     *DroppedIP `json:"dropped,omitempty"`
	Flow        *Flow      `json:"flow,omitempty"`
	FullInfo    *FullInfo  `json:"full_info,omitempty"`
	Parent      *Process   `json:"parent,omitempty"`
	Process     *Process   `json:"process,omitempty"`
	Resolve     *string    `json:"resolve"`
	ResolveFlow *Flow      `json:"resolve_flow,omitempty"`
}

type DroppedIP struct {
	Icmp        ICMP        `json:"icmp,omitempty"`
	IPVersion   *int        `json:"ip_version,omitempty"`
	Local       *Node       `json:"local,omitempty"`
	Properties  *Properties `json:"properties,omitempty"`
	Proto       *string     `json:"proto,omitempty"`
	Remote      *Node       `json:"remote,omitempty"`
	ServicePort *int        `json:"service_port,omitempty"`
}

type FullInfo struct {
	Ancestry *[]Process                         `json:"ancestry,omitempty"`
	Files    *map[string]map[string]interface{} `json:"files,omitempty"`
	Flows    *[]FlowSimple                      `json:"flows,omitempty"`
}

type FlowSimple struct {
	Icmp        *ICMP     `json:"icmp,omitempty"`
	IPVersion   *int      `json:"ip_version,omitempty"`
	Local       *Node     `json:"local,omitempty"`
	Proto       *string   `json:"proto,omitempty"`
	Remote      *Node     `json:"remote,omitempty"`
	ServicePort *int      `json:"service_port,omitempty"`
	Settings    *Settings `json:"settings,omitempty"`
}

type Flow struct {
	FlowSimple
	Properties *Properties `json:"properties,omitempty"`
}

type Properties struct {
	Egress     *bool `json:"egress,omitempty"`
	Ended      *bool `json:"ended,omitempty"`
	Incoming   *bool `json:"incoming,omitempty"`
	Ingress    *bool `json:"ingress,omitempty"`
	Ongoing    *bool `json:"ongoing,omitempty"`
	Outgoing   *bool `json:"outgoing,omitempty"`
	Started    *bool `json:"started,omitempty"`
	Terminated *bool `json:"terminated,omitempty"`
	Terminator *bool `json:"terminator,omitempty"`
}

type Settings struct {
	Direction   *string `json:"direction,omitempty"`
	EndedBy     *string `json:"ended_by,omitempty"`
	InitiatedBy *string `json:"initiated_by,omitempty"`
	Status      *string `json:"status,omitempty"`
}

type Node struct {
	Address *string   `json:"address,omitempty"`
	Name    *string   `json:"name,omitempty"`
	Names   *[]string `json:"names,omitempty"`
	Port    *int      `json:"port,omitempty"`
}

type ICMP struct {
	Code *string `json:"code,omitempty"`
	Type *string `json:"type,omitempty"`
}

type Process struct {
	Args       *string `json:"args,omitempty"`
	Cmd        *string `json:"cmd,omitempty"`
	Comm       *string `json:"comm,omitempty"`
	Exe        *string `json:"exe,omitempty"`
	Exit       *string `json:"exit,omitempty"`
	Loader     *string `json:"loader,omitempty"`
	PID        *int    `json:"pid,omitempty"`
	PpID       *int    `json:"ppid,omitempty"`
	PrevArgs   *string `json:"prev_args,omitempty"`
	PrevExe    *string `json:"prev_exe,omitempty"`
	PrevLoader *string `json:"prev_loader,omitempty"`
	Retcode    *int    `json:"retcode,omitempty"`
	Start      *string `json:"start,omitempty"`
	UID        *int    `json:"uid,omitempty"`
}

// IngestEventResult is the result of the IngestEvent method of the service.
type IngestEventResult struct {
	ID      string `json:"id"`
	Created bool   `json:"created"`
	Updated bool   `json:"updated"`
}

// IngestedEvent is the API response for the IngestEvent method.
type IngestedEvent struct {
	ID string `json:"id"`
}
