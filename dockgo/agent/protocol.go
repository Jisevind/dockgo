package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"dockgo/api"
	"dockgo/stacks"
)

// Message types. All messages are JSON envelopes with a request_id, sent over
// a single persistent WebSocket channel per agent.
const (
	// Server -> Agent: request messages (a request_id is mandatory).
	TypeRegister        = "register"
	TypeContainersList  = "containers_list"
	TypeScan            = "scan"
	TypeUpdate          = "update"
	TypeContainerAction = "container_action"
	TypeContainerLogs   = "container_logs"
	TypeServerStats     = "server_stats"
	TypeStackList       = "stack_list"
	TypeStackGet        = "stack_get"
	TypeStackCreate     = "stack_create"
	TypeStackUpdate     = "stack_update"
	TypeStackDelete     = "stack_delete"
	TypeStackAction     = "stack_action"
	TypeStackValidate   = "stack_validate"
	TypeStackHistory    = "stack_history"
	TypeStackContainers = "stack_containers"
	TypeStackDiscover   = "stack_discover"
	TypeDisconnect      = "disconnect"

	// Agent -> Server: response/stream messages.
	TypeWelcome   = "welcome"
	TypeProgress  = "progress"
	TypeResult    = "result"
	TypeHeartbeat = "heartbeat"
	TypePong      = "pong"
	TypeError     = "error"
)

// Progress kinds carried by progress messages.
const (
	ProgressScan   = "scan"
	ProgressUpdate = "update"
	ProgressLog    = "log"
	ProgressStack  = "stack"
)

// Envelope is the wire format for every message in either direction.
type Envelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// NewEnvelope builds an envelope from a typed payload.
func NewEnvelope(msgType, requestID string, data any) (Envelope, error) {
	var raw json.RawMessage
	if data != nil {
		bytes, err := json.Marshal(data)
		if err != nil {
			return Envelope{}, fmt.Errorf("marshal %s payload: %w", msgType, err)
		}
		raw = bytes
	}

	return Envelope{
		ID:        "",
		Type:      msgType,
		RequestID: requestID,
		Data:      raw,
	}, nil
}

// Marshal returns the JSON bytes for an envelope.
func (e Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Decode unmarshals Data into the destination pointer.
func (e Envelope) Decode(dst any) error {
	if len(e.Data) == 0 {
		return nil
	}
	return json.Unmarshal(e.Data, dst)
}

// RegisterRequest is the first message an agent sends on a new channel.
// On reconnect the agent may include its learned agent_id alongside the key,
// and a previously issued JWT (Authorization-style) to authenticate without
// presenting the key again.
type RegisterRequest struct {
	Key      string `json:"key"`
	JWT      string `json:"jwt,omitempty"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	AgentID  string `json:"agent_id,omitempty"`
	Name     string `json:"name,omitempty"`
}

// WelcomeResponse acknowledges a successful handshake.
type WelcomeResponse struct {
	AgentID       string   `json:"agent_id"`
	AgentName     string   `json:"agent_name"`
	ServerVersion string   `json:"server_version"`
	Capabilities  []string `json:"capabilities"`
	DockerStatus  string   `json:"docker_status"`
	JWT           string   `json:"jwt,omitempty"`
	HeartbeatSec  int      `json:"heartbeat_sec,omitempty"`
}

// Capabilities advertised by an agent.
const (
	CapContainers = "containers"
	CapScan       = "scan"
	CapUpdate     = "update"
	CapLogs       = "logs"
	CapStats      = "stats"
	CapStacks     = "stacks"
)

// Request carries the decoded request payload for a dispatched operation.
type Request struct {
	ID   string
	Type string
	Data json.RawMessage
}

// ContainersListRequest is empty (the agent lists all containers).

// ScanRequest requests an update scan.
type ScanRequest struct {
	Force bool `json:"force"`
	// Filter optionally limits the scan to a single container name.
	Filter string `json:"filter,omitempty"`
}

// UpdateRequest updates a single container.
type UpdateRequest struct {
	Name            string `json:"name"`
	Safe            bool   `json:"safe"`
	PreserveNetwork bool   `json:"preserve_network"`
}

// ContainerActionRequest controls a container lifecycle action.
type ContainerActionRequest struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

// ContainerLogsRequest streams container logs.
type ContainerLogsRequest struct {
	Name string `json:"name"`
}

// StackRequest carries the full stack object in-band for stack operations
// executed on the agent host. The server is the single source of truth.
type StackRequest struct {
	Stack stacks.Stack `json:"stack"`
}

// StackActionRequest carries a stack plus the action to run.
type StackActionRequest struct {
	Stack  stacks.Stack `json:"stack"`
	Action string       `json:"action"`
}

// StackDeleteRequest requests stack registration deletion (server-side) with
// agent-side cleanup.
type StackDeleteRequest struct {
	Stack stacks.Stack `json:"stack"`
}

// StackHistoryRequest requests stack history for an agent-hosted stack.
type StackHistoryRequest struct {
	StackID string `json:"stack_id"`
	Limit   int    `json:"limit,omitempty"`
	Action  string `json:"action,omitempty"`
	Status  string `json:"status,omitempty"`
	Source  string `json:"source,omitempty"`
}

// StackContainersRequest requests the runtime containers of an agent stack.
type StackContainersRequest struct {
	Stack stacks.Stack `json:"stack"`
}

// StackDiscoverRequest discovers compose projects on the agent host.
type StackDiscoverRequest struct{}

// ProgressData is the payload of a progress message.
type ProgressData struct {
	ProgressType string                 `json:"progress_type"`
	Progress     *api.ProgressEvent     `json:"progress,omitempty"`
	PullProgress *api.PullProgressEvent `json:"pull_progress,omitempty"`
	Line         string                 `json:"line,omitempty"`
	Stack        string                 `json:"stack,omitempty"`
	Action       string                 `json:"action,omitempty"`
}

// ResultData is the payload of a terminal result message. The Value field is
// the raw JSON of the operation result (or null).
type ResultData struct {
	Error string          `json:"error,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ServerStatsData mirrors the server's stats response shape.
type ServerStatsData struct {
	CPUPercent float64 `json:"cpu_percent"`
	RAMUsed    uint64  `json:"ram_used"`
	RAMTotal   uint64  `json:"ram_total"`
	DiskUsed   uint64  `json:"disk_used"`
	DiskTotal  uint64  `json:"disk_total"`
}

// ContainerListEntry mirrors the shape produced by the server's handleContainers.
type ContainerListEntry struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Image             string            `json:"image"`
	Tag               string            `json:"tag"`
	State             string            `json:"state"`
	Status            string            `json:"status"`
	UpdateAvailable   bool              `json:"update_available"`
	ComposeProject    string            `json:"compose_project"`
	ComposeService    string            `json:"compose_service"`
	ComposeWorkingDir string            `json:"compose_working_dir"`
	StackManaged      bool              `json:"stack_managed"`
	StackRegistered   bool              `json:"stack_registered"`
	StackID           string            `json:"stack_id"`
	StackName         string            `json:"stack_name"`
	LastUpdateError   string            `json:"last_update_error,omitempty"`
	LastUpdateAttempt time.Time         `json:"last_update_attempt,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

// StackDetailResult is the result of stack_get on the agent side.
type StackDetailResult struct {
	Stack         stacks.Stack             `json:"stack"`
	Validation    *stacks.ValidationResult `json:"validation,omitempty"`
	ResolvedPaths map[string]any           `json:"resolved_paths,omitempty"`
	Containers    []map[string]string      `json:"containers,omitempty"`
	StatusSummary map[string]any           `json:"status_summary,omitempty"`
}

// StackActionResult is the result of a stack action (deploy/pull/restart/down).
type StackActionResult struct {
	Success bool   `json:"success"`
	Action  string `json:"action"`
}

// StackListResult lists stacks hosted on the agent (server-side list is authoritative).
type StackListResult struct {
	Stacks []stacks.Stack `json:"stacks"`
}

// ContainerActionResult is the result of a container lifecycle action.
type ContainerActionResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// UpdateResult is the result of a container update operation.
type UpdateResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// LogsResult terminates a container log stream.
type LogsResult struct {
	Done bool `json:"done"`
}

// StackStatusResult carries a stack status summary computed on the agent host.
type StackStatusResult struct {
	StatusSummary map[string]any `json:"status_summary"`
}

// StackValidateResult carries a validation result computed on the agent host.
type StackValidateResult struct {
	Validation stacks.ValidationResult `json:"validation"`
}

// StackDiscoverCandidate mirrors the server's discovery candidate shape.
type StackDiscoverCandidate struct {
	Project              string   `json:"project"`
	WorkingDir           string   `json:"working_dir"`
	Services             []string `json:"services"`
	Registered           bool     `json:"registered"`
	ConfigFiles          []string `json:"config_files,omitempty"`
	ComposeFiles         []string `json:"compose_files,omitempty"`
	SuggestedComposeFile string   `json:"suggested_compose_file,omitempty"`
	SuggestedEnvFile     string   `json:"suggested_env_file,omitempty"`
}

// StackDiscoverResult returns discovered compose projects from the agent host.
type StackDiscoverResult struct {
	Candidates []StackDiscoverCandidate `json:"candidates"`
}

// StackReconcileResult reports how many runtime containers were bound to a stack.
type StackReconcileResult struct {
	Count int `json:"count"`
}

// StackContainersResult returns runtime containers for an agent-hosted stack.
type StackContainersResult struct {
	Containers []map[string]string `json:"containers"`
}
