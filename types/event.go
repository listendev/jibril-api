// Package types contains all the required clients for marshal/unmarshal requests and responses from/to jibril-server.
package types

import (
	"time"

	"github.com/listendev/jibril-api/types/errs"
)

const (
	ErrInvalidEventKind = errs.InvalidArgumentError("invalid event kind")
	ErrIDcannotBeEmpty  = errs.InvalidArgumentError("id is required")
)

type EventKind string

const (
	// Network Flow Events.
	EventKindDropIP     EventKind = "drop_ip"
	EventKindDropDomain EventKind = "drop_domain"
	EventKindFlow       EventKind = "flow"

	// File Access Detection Events.
	EventKindCapabilitiesModification      EventKind = "capabilities_modification"
	EventKindCodeModificationThroughProcfs EventKind = "code_modification_through_procfs"
	EventKindCorePatternAccess             EventKind = "core_pattern_access"
	EventKindCPUFingerprint                EventKind = "cpu_fingerprint"
	EventKindCredentialsFilesAccess        EventKind = "credentials_files_access"
	EventKindFilesystemFingerprint         EventKind = "filesystem_fingerprint"
	EventKindJavaDebugLibLoad              EventKind = "java_debug_lib_load"
	EventKindJavaInstrumentLibLoad         EventKind = "java_instrument_lib_load"
	EventKindMachineFingerprint            EventKind = "machine_fingerprint"
	EventKindOSFingerprint                 EventKind = "os_fingerprint"
	EventKindOSNetworkFingerprint          EventKind = "os_network_fingerprint"
	EventKindOSStatusFingerprint           EventKind = "os_status_fingerprint"
	EventKindPackageRepoConfigModification EventKind = "package_repo_config_modification"
	EventKindPAMConfigModification         EventKind = "pam_config_modification"
	EventKindSchedDebugAccess              EventKind = "sched_debug_access"
	EventKindShellConfigModification       EventKind = "shell_config_modification"
	EventKindSSLCertificateAccess          EventKind = "ssl_certificate_access"
	EventKindSudoersModification           EventKind = "sudoers_modification"
	EventKindSysrqAccess                   EventKind = "sysrq_access"
	EventKindUnprivilegedBPFConfigAccess   EventKind = "unprivileged_bpf_config_access"
	EventKindGlobalShlibModification       EventKind = "global_shlib_modification"
	EventKindEnvironReadFromProcfs         EventKind = "environ_read_from_procfs"
	EventKindBinarySelfDeletion            EventKind = "binary_self_deletion"
	EventKindCryptoMinerFiles              EventKind = "crypto_miner_files"
	EventKindAuthLogsTamper                EventKind = "auth_logs_tamper"

	// Execution Detection Events.
	EventKindBinaryExecutedByLoader EventKind = "binary_executed_by_loader"
	EventKindCodeOnTheFly           EventKind = "code_on_the_fly"
	EventKindDataEncoderExec        EventKind = "data_encoder_exec"
	EventKindDenialOfServiceTools   EventKind = "denial_of_service_tools"
	EventKindExecFromUnusualDir     EventKind = "exec_from_unusual_dir"
	EventKindFileAttributeChange    EventKind = "file_attribute_change"
	EventKindHiddenELFExec          EventKind = "hidden_elf_exec"
	EventKindInterpreterShellSpawn  EventKind = "interpreter_shell_spawn"
	EventKindNetFilecopyToolExec    EventKind = "net_filecopy_tool_exec"
	EventKindNetMITMToolExec        EventKind = "net_mitm_tool_exec"
	EventKindNetScanToolExec        EventKind = "net_scan_tool_exec"
	EventKindNetSniffToolExec       EventKind = "net_sniff_tool_exec"
	EventKindNetSuspiciousToolExec  EventKind = "net_suspicious_tool_exec"
	EventKindNetSuspiciousToolShell EventKind = "net_suspicious_tool_shell"
	EventKindPasswdUsage            EventKind = "passwd_usage"
	EventKindRuncSuspiciousExec     EventKind = "runc_suspicious_exec"
	EventKindWebserverExec          EventKind = "webserver_exec"
	EventKindWebserverShellExec     EventKind = "webserver_shell_exec"
	EventKindCryptoMinerExecution   EventKind = "crypto_miner_execution"

	// Network Peer Detection Events.
	EventKindAdultDomainAccess      EventKind = "adult_domain_access"
	EventKindBadwareDomainAccess    EventKind = "badware_domain_access"
	EventKindDynDNSDomainAccess     EventKind = "dyndns_domain_access"
	EventKindFakeDomainAccess       EventKind = "fake_domain_access"
	EventKindGamblingDomainAccess   EventKind = "gambling_domain_access"
	EventKindPiracyDomainAccess     EventKind = "piracy_domain_access"
	EventKindPlaintextCommunication EventKind = "plaintext_communication"
	EventKindThreatDomainAccess     EventKind = "threat_domain_access"
	EventKindTrackingDomainAccess   EventKind = "tracking_domain_access"
	EventKindVPNLikeDomainAccess    EventKind = "vpnlike_domain_access"
)

func (k EventKind) OK() bool {
	for _, allowed := range [...]EventKind{
		EventKindDropIP,
		EventKindDropDomain,
		EventKindFlow,
		EventKindCapabilitiesModification,
		EventKindCodeModificationThroughProcfs,
		EventKindCorePatternAccess,
		EventKindCPUFingerprint,
		EventKindCredentialsFilesAccess,
		EventKindFilesystemFingerprint,
		EventKindJavaDebugLibLoad,
		EventKindJavaInstrumentLibLoad,
		EventKindMachineFingerprint,
		EventKindOSFingerprint,
		EventKindOSNetworkFingerprint,
		EventKindOSStatusFingerprint,
		EventKindPackageRepoConfigModification,
		EventKindPAMConfigModification,
		EventKindSchedDebugAccess,
		EventKindShellConfigModification,
		EventKindSSLCertificateAccess,
		EventKindSudoersModification,
		EventKindSysrqAccess,
		EventKindUnprivilegedBPFConfigAccess,
		EventKindGlobalShlibModification,
		EventKindEnvironReadFromProcfs,
		EventKindBinarySelfDeletion,
		EventKindCryptoMinerFiles,
		EventKindAuthLogsTamper,
		EventKindBinaryExecutedByLoader,
		EventKindCodeOnTheFly,
		EventKindDataEncoderExec,
		EventKindDenialOfServiceTools,
		EventKindExecFromUnusualDir,
		EventKindFileAttributeChange,
		EventKindHiddenELFExec,
		EventKindInterpreterShellSpawn,
		EventKindNetFilecopyToolExec,
		EventKindNetMITMToolExec,
		EventKindNetScanToolExec,
		EventKindNetSniffToolExec,
		EventKindNetSuspiciousToolExec,
		EventKindNetSuspiciousToolShell,
		EventKindPasswdUsage,
		EventKindRuncSuspiciousExec,
		EventKindWebserverExec,
		EventKindWebserverShellExec,
		EventKindCryptoMinerExecution,
		EventKindAdultDomainAccess,
		EventKindBadwareDomainAccess,
		EventKindDynDNSDomainAccess,
		EventKindFakeDomainAccess,
		EventKindGamblingDomainAccess,
		EventKindPiracyDomainAccess,
		EventKindPlaintextCommunication,
		EventKindThreatDomainAccess,
		EventKindTrackingDomainAccess,
		EventKindVPNLikeDomainAccess,
	} {
		if k == allowed {
			return true
		}
	}

	return false
}

func (e *CreateOrUpdateEvent) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmpty
	}

	if !e.Kind.OK() {
		return ErrInvalidEventKind
	}

	return nil
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

// CreateOrUpdateEvent is used for creating or updating events.
// It includes the agent ID but doesn't return the full agent details.
type CreateOrUpdateEvent struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"-"` // Internal field, not exposed in JSON
	Data      EventData `json:"data"`
	Kind      EventKind `json:"kind"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Event is something that happened in the system.
// This is used for retrieving events and includes the full agent details.
type Event struct {
	ID        string    `json:"id"`
	Agent     Agent     `json:"agent"`
	Data      EventData `json:"data"`
	Kind      EventKind `json:"kind"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type EventData struct {
	Dropped     *DroppedIP `json:"dropped,omitempty"`
	Flow        *Flow      `json:"flow,omitempty"`
	FullInfo    *FullInfo  `json:"full_info,omitempty"`
	Parent      *Process   `json:"parent,omitempty"`
	Process     *Process   `json:"process,omitempty"`
	Resolve     *string    `json:"resolve"`
	ResolveFlow *Flow      `json:"resolve_flow,omitempty"`
	Note        *string    `json:"note,omitempty"`
	Head        *EventHead `json:"head,omitempty"`
}

// EventHead represents the metadata for an event.
type EventHead struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Format        string `json:"format"`
	Description   string `json:"description"`
	Documentation string `json:"documentation"`
	Category      string `json:"category"`
	Mechanism     string `json:"mechanism"`
	Method        string `json:"method"`
	Importance    string `json:"importance"`
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

// EventCreatedOrUpdated represents the response when an event is successfully created or updated.
type EventCreatedOrUpdated struct {
	ID        string    `json:"id"`
	Created   bool      `json:"created"`
	UpdatedAt time.Time `json:"updated_at"`
}
