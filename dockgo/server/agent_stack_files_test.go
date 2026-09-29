package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dockgo/agent"
	"dockgo/stacks"

	"github.com/coder/websocket"
)

// The paths below are the agent host's, which is where an agent-hosted stack's
// files live. The server never resolves them: it proxies kind/index to the agent.
const (
	agentFileWorkingDir  = "/opt/stacks/remote-editor"
	agentFileComposePath = agentFileWorkingDir + "/compose.yaml"
	agentFileOverride    = agentFileWorkingDir + "/compose.override.yaml"
	agentFileEnvPath     = agentFileWorkingDir + "/.env"
)

// agentFileTargetValue is the target the fake agent reports: the file it
// resolved, carrying the size it had before anything was written.
func agentFileTargetValue(kind string, index int, label string, path string, size int64) stacks.FileTarget {
	return stacks.FileTarget{
		Kind:     kind,
		Index:    index,
		Label:    label,
		Path:     path,
		Size:     size,
		Exists:   true,
		Editable: true,
	}
}

// saveAgentHostedStack registers a stack for agentID in the server store. The
// store is the source of truth for the stack; only its files live on the agent.
func saveAgentHostedStack(t *testing.T, srv *Server, agentID string) stacks.Stack {
	t.Helper()

	stack, err := srv.StackStore.Save(stacks.Stack{
		Name:         "remote-editor",
		ProjectName:  "remote-editor",
		Kind:         stacks.KindComposeFiles,
		WorkingDir:   agentFileWorkingDir,
		ComposeFiles: []string{agentFileComposePath, agentFileOverride},
		EnvFiles:     []string{agentFileEnvPath},
		PathMode:     stacks.PathModeHostNative,
		AgentID:      agentID,
	})
	if err != nil {
		t.Fatalf("StackStore.Save() error = %v", err)
	}
	return stack
}

// newAgentFileProxyFixture wires the shared agent harness with one agent-hosted
// stack and a connected fake agent, so a test can drive the proxy end to end.
func newAgentFileProxyFixture(t *testing.T, agentName string) (*Server, *websocket.Conn, context.Context, stacks.Stack, string) {
	t.Helper()

	srv, _ := newTestServerWithAgent(t)

	agentRec, _, err := srv.AgentStore.Create(agentName)
	if err != nil {
		t.Fatalf("AgentStore.Create() error = %v", err)
	}
	conn, ctx := connectTestAgent(t, srv, srv.agentTestMux(), agentRec)
	if !srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("agent not online after handshake")
	}

	// Tear the connection down and wait for the agent to go offline so the async
	// offline-state persist completes before t.TempDir is removed.
	t.Cleanup(func() {
		_ = conn.CloseNow()
		deadline := time.Now().Add(3 * time.Second)
		for srv.AgentManager.IsOnline(agentRec.ID) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
	})

	return srv, conn, ctx, saveAgentHostedStack(t, srv, agentRec.ID), agentRec.ID
}

// agentFileRoundTrip drives one request through handleAgentStacksRoute against
// the connected fake agent: it reads the request the proxy dispatched, answers
// it with reply's ResultData and returns the HTTP response once the handler has
// finished.
func agentFileRoundTrip(
	t *testing.T,
	srv *Server,
	conn *websocket.Conn,
	ctx context.Context,
	req *http.Request,
	wantType string,
	reply func(t *testing.T, request agent.Envelope) agent.ResultData,
) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleAgentStacksRoute(rec, req)
	}()

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(%s request) error = %v", wantType, err)
	}
	var request agent.Envelope
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatalf("request envelope unmarshal error = %v", err)
	}
	if request.Type != wantType {
		t.Fatalf("dispatched %q, want %q", request.Type, wantType)
	}

	env, err := agent.NewEnvelope(agent.TypeResult, request.RequestID, reply(t, request))
	if err != nil {
		t.Fatalf("agent.NewEnvelope() error = %v", err)
	}
	bytes, _ := env.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, bytes); err != nil {
		t.Fatalf("conn.Write(%s result) error = %v", wantType, err)
	}

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("proxy handler for %s never returned", wantType)
	}
	return rec
}

// decodeAgentFileRequest decodes the StackFileRequest the proxy dispatched.
func decodeAgentFileRequest(t *testing.T, request agent.Envelope) agent.StackFileRequest {
	t.Helper()

	var payload agent.StackFileRequest
	if err := request.Decode(&payload); err != nil {
		t.Fatalf("decode %s request error = %v", request.Type, err)
	}
	return payload
}

// decodeAgentFileWriteRequest decodes the StackFileWriteRequest the proxy
// dispatched.
func decodeAgentFileWriteRequest(t *testing.T, request agent.Envelope) agent.StackFileWriteRequest {
	t.Helper()

	var payload agent.StackFileWriteRequest
	if err := request.Decode(&payload); err != nil {
		t.Fatalf("decode %s request error = %v", request.Type, err)
	}
	return payload
}

func TestAgentStackFileListProxiesAgentListing(t *testing.T) {
	srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-list")

	rec := agentFileRoundTrip(t, srv, conn, ctx,
		httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/files?agent="+agentID, nil),
		agent.TypeStackFileList,
		func(t *testing.T, request agent.Envelope) agent.ResultData {
			payload := decodeAgentFileRequest(t, request)
			if payload.Stack.ID != stack.ID {
				t.Fatalf("dispatched stack id = %q, want %q", payload.Stack.ID, stack.ID)
			}
			value, err := json.Marshal(map[string]any{"files": []stacks.FileTarget{
				agentFileTargetValue(stacks.FileKindCompose, 0, "compose.yaml", agentFileComposePath, 21),
			}})
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			return agent.ResultData{Value: value}
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// The listing must keep the agent's {"files": ...} shape, which is the shape
	// the local route serves.
	var body struct {
		Files []stacks.FileTarget `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
	}
	if len(body.Files) != 1 {
		t.Fatalf("files = %+v, want the agent's single target", body.Files)
	}
	if body.Files[0].Label != "compose.yaml" || body.Files[0].Path != agentFileComposePath || !body.Files[0].Editable {
		t.Fatalf("files[0] = %+v, want the agent's editable compose target", body.Files[0])
	}
}

func TestAgentStackFileReadProxiesAgentContent(t *testing.T) {
	srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-read")

	const content = "services:\n  web:\n    image: busybox:1.36\n"

	// Index 1 selects the second compose file, so this pins the index the proxy
	// sends rather than assuming the first file.
	rec := agentFileRoundTrip(t, srv, conn, ctx,
		httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/file?agent="+agentID+"&kind=compose&index=1", nil),
		agent.TypeStackFileRead,
		func(t *testing.T, request agent.Envelope) agent.ResultData {
			payload := decodeAgentFileRequest(t, request)
			if payload.Stack.ID != stack.ID || payload.Kind != stacks.FileKindCompose || payload.Index != 1 {
				t.Fatalf("dispatched request = %+v, want the stack with compose index 1", payload)
			}
			value, err := json.Marshal(map[string]any{
				"target":  agentFileTargetValue(stacks.FileKindCompose, 1, "compose.override.yaml", agentFileOverride, int64(len(content))),
				"content": content,
			})
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			return agent.ResultData{Value: value}
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Target  stacks.FileTarget `json:"target"`
		Content string            `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
	}
	if body.Content != content {
		t.Fatalf("content = %q, want %q", body.Content, content)
	}
	if body.Target.Label != "compose.override.yaml" || body.Target.Path != agentFileOverride {
		t.Fatalf("target = %+v, want the target the agent read", body.Target)
	}
}

func TestAgentStackFileValidateProxiesDraft(t *testing.T) {
	srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-validate")

	draft := "FOO=bar\n"

	rec := agentFileRoundTrip(t, srv, conn, ctx,
		httptest.NewRequest(http.MethodPost,
			"/api/stacks/"+stack.ID+"/file/validate?agent="+agentID+"&kind=env&index=0",
			strings.NewReader(`{"content":"FOO=bar\n"}`)),
		agent.TypeStackFileValidate,
		func(t *testing.T, request agent.Envelope) agent.ResultData {
			payload := decodeAgentFileWriteRequest(t, request)
			if payload.Stack.ID != stack.ID || payload.Kind != stacks.FileKindEnv || payload.Index != 0 {
				t.Fatalf("dispatched request = %+v, want the stack with env index 0", payload)
			}
			if payload.Content != draft {
				t.Fatalf("dispatched content = %q, want the draft %q", payload.Content, draft)
			}
			return agent.ResultData{Value: json.RawMessage(`{"valid":true,"errors":[]}`)}
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// The draft check answers with the agent's own syntax result, the shape the
	// local route returns.
	var body struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
	}
	if !body.Valid {
		t.Fatalf("body = %s, want the agent's valid syntax result", rec.Body.String())
	}
}

func TestAgentStackFileWriteRecordsHistoryOnSuccess(t *testing.T) {
	// The size the agent resolved before it wrote, so the recorded delta is the
	// one the local write would report.
	const previousSize = 5

	draft := "services: {}\n"

	tests := []struct {
		name       string
		kind       string
		query      string
		label      string
		path       string
		index      int
		wantAction string
		wantDelta  string
	}{
		{
			name:       "compose file",
			kind:       stacks.FileKindCompose,
			query:      "kind=compose&index=0",
			label:      "compose.yaml",
			path:       agentFileComposePath,
			index:      0,
			wantAction: "edit_compose",
			wantDelta:  "compose.yaml updated (compose, +8 bytes)",
		},
		{
			name:       "env file",
			kind:       stacks.FileKindEnv,
			query:      "kind=env&index=0",
			label:      ".env",
			path:       agentFileEnvPath,
			index:      0,
			wantAction: "edit_env",
			wantDelta:  ".env updated (env, +8 bytes)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-write-"+tc.kind)

			if entries := srv.StackHistory.ListByStack(stack.ID, 10); len(entries) != 0 {
				t.Fatalf("history = %+v before the save, want none", entries)
			}

			rec := agentFileRoundTrip(t, srv, conn, ctx,
				httptest.NewRequest(http.MethodPut,
					"/api/stacks/"+stack.ID+"/file?agent="+agentID+"&"+tc.query,
					strings.NewReader(`{"content":"services: {}\n"}`)),
				agent.TypeStackFileWrite,
				func(t *testing.T, request agent.Envelope) agent.ResultData {
					payload := decodeAgentFileWriteRequest(t, request)
					if payload.Stack.ID != stack.ID || payload.Kind != tc.kind || payload.Index != tc.index {
						t.Fatalf("dispatched request = %+v, want the stack with %s index %d", payload, tc.kind, tc.index)
					}
					if payload.Content != draft {
						t.Fatalf("dispatched content = %q, want %q", payload.Content, draft)
					}
					value, err := json.Marshal(map[string]any{
						"target": agentFileTargetValue(tc.kind, tc.index, tc.label, tc.path, previousSize),
					})
					if err != nil {
						t.Fatalf("Marshal() error = %v", err)
					}
					return agent.ResultData{Value: value}
				})

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
			}

			// The save answers with the shape the local write returns.
			var body struct {
				Target stacks.FileTarget `json:"target"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
			}
			if body.Target.Label != tc.label || body.Target.Path != tc.path {
				t.Fatalf("target = %+v, want the target the agent wrote", body.Target)
			}

			// The agent keeps no stack history: the server owns the store, so the
			// proxy records the entry the local write records.
			entries := srv.StackHistory.ListByStack(stack.ID, 10)
			if len(entries) != 1 {
				t.Fatalf("history = %+v, want one entry for the save", entries)
			}
			entry := entries[0]
			if entry.Action != tc.wantAction || entry.Status != "success" || entry.Source != "system" {
				t.Fatalf("history entry = %+v, want action %q with status success from system", entry, tc.wantAction)
			}
			if entry.Message != tc.wantDelta {
				t.Fatalf("history message = %q, want %q", entry.Message, tc.wantDelta)
			}
		})
	}
}

// TestAgentStackFileWriteDistinguishesFailedRollback pins the failure this phase
// must not ship: a save whose previous content could NOT be restored must never
// be answered as the clean refusal, in which the file was restored. The agent
// sends the message and no code, so the proxy classifies by text.
func TestAgentStackFileWriteDistinguishesFailedRollback(t *testing.T) {
	const (
		cleanValidation = `file failed compose validation: service "web" refers to undefined network "nope"`
		failedRollback  = "rollback failed: the previous content could not be restored: " +
			"open /opt/stacks/remote-editor/compose.yaml: permission denied"
	)

	tests := []struct {
		name         string
		message      string
		wantStatus   int
		wantRestored bool
	}{
		{
			name:         "clean validation failure restored the file",
			message:      cleanValidation,
			wantStatus:   http.StatusUnprocessableEntity,
			wantRestored: true,
		},
		{
			name:         "failed rollback left the file invalid",
			message:      failedRollback,
			wantStatus:   http.StatusInternalServerError,
			wantRestored: false,
		},
	}

	statuses := make(map[string]int, len(tests))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-refusal-"+tc.name[:1])

			rec := agentFileRoundTrip(t, srv, conn, ctx,
				httptest.NewRequest(http.MethodPut,
					"/api/stacks/"+stack.ID+"/file?agent="+agentID+"&kind=compose&index=0",
					strings.NewReader(`{"content":"services: {}\n"}`)),
				agent.TypeStackFileWrite,
				func(t *testing.T, request agent.Envelope) agent.ResultData {
					return agent.ResultData{Error: tc.message}
				})

			statuses[tc.name] = rec.Code
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
			}
			if body["error"] != tc.message {
				t.Fatalf("error = %v, want the agent's message %q carried through", body["error"], tc.message)
			}
			restored, ok := body["rolled_back"]
			if !ok {
				t.Fatalf("body = %s, want an explicit rolled_back flag", rec.Body.String())
			}
			if restored != tc.wantRestored {
				t.Fatalf("rolled_back = %v, want %v (body=%s)", restored, tc.wantRestored, rec.Body.String())
			}

			// A refused save is never recorded as a success, and a failed
			// rollback in particular must not leave a "success" entry behind.
			for _, entry := range srv.StackHistory.ListByStack(stack.ID, 10) {
				if entry.Status == "success" {
					t.Fatalf("history entry = %+v, want no success entry for a refused save", entry)
				}
			}
		})
	}

	// The two refusals must not share a status. If they did, a client that reads
	// the status alone would report the file as restored while the rejected
	// draft is still on the agent's disk.
	if statuses["clean validation failure restored the file"] == statuses["failed rollback left the file invalid"] {
		t.Fatalf("both refusals answer status %d, so a client cannot tell a restored file from one left invalid",
			statuses["failed rollback left the file invalid"])
	}
}

// TestAgentStackFileRefusalsMapToLocalStatuses checks the agent's sentinel
// failures map onto the same status the local route answers for the same
// condition, on both the read and the write path, so a client does not see
// different statuses depending on which host holds the stack.
func TestAgentStackFileRefusalsMapToLocalStatuses(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    int
	}{
		{
			name:    "missing file",
			message: "file does not exist: " + agentFileComposePath,
			want:    http.StatusNotFound,
		},
		{
			name:    "directory in place of a file",
			message: "file is not a regular file: " + agentFileComposePath,
			want:    http.StatusForbidden,
		},
		{
			name:    "file over the cap",
			message: "file exceeds the editable size limit: " + agentFileComposePath + " is 1048577 bytes",
			want:    http.StatusRequestEntityTooLarge,
		},
		{
			name:    "file outside the agent's allow-list",
			message: "path is not within the allowed compose paths: /etc/passwd (allowed: [/opt/stacks])",
			want:    http.StatusForbidden,
		},
		{
			name:    "git-kind stack",
			message: "git-kind stacks are not supported on remote agents",
			want:    http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		for _, op := range []struct {
			name   string
			method string
			opType string
		}{
			{name: "read", method: http.MethodGet, opType: agent.TypeStackFileRead},
			{name: "write", method: http.MethodPut, opType: agent.TypeStackFileWrite},
		} {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-status-"+op.name)

				rec := agentFileRoundTrip(t, srv, conn, ctx,
					httptest.NewRequest(op.method,
						"/api/stacks/"+stack.ID+"/file?agent="+agentID+"&kind=compose&index=0",
						strings.NewReader(`{"content":"services: {}\n"}`)),
					op.opType,
					func(t *testing.T, request agent.Envelope) agent.ResultData {
						return agent.ResultData{Error: tc.message}
					})

				if rec.Code != tc.want {
					t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
				}

				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
				}
				if body["error"] != tc.message {
					t.Fatalf("error = %v, want the agent's message %q carried through", body["error"], tc.message)
				}
			})
		}
	}
}

// TestAgentStackFileSelectorOutsideTheStackIsRejectedLocally pins that a
// selector the stack does not have is answered with the local route's 400 rather
// than being sent to the agent, which could only fail with a status of its own.
// The agent is deliberately left offline here: a dispatch would answer 503.
func TestAgentStackFileSelectorOutsideTheStackIsRejectedLocally(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	agentRec, _, err := srv.AgentStore.Create("file-selector")
	if err != nil {
		t.Fatalf("AgentStore.Create() error = %v", err)
	}
	stack := saveAgentHostedStack(t, srv, agentRec.ID)

	tests := []struct {
		name  string
		query string
		want  string
	}{
		{name: "missing kind", query: "index=0", want: "kind is required"},
		{name: "missing index", query: "kind=compose", want: "index is required"},
		{name: "non-numeric index", query: "kind=compose&index=abc", want: "index must be an integer"},
		{name: "unsupported kind", query: "kind=bogus&index=0", want: "unsupported file kind: bogus"},
		{name: "negative index", query: "kind=env&index=-1", want: "index must not be negative"},
		{name: "compose index past the end", query: "kind=compose&index=9", want: "compose index 9 is out of range"},
		{name: "env index past the end", query: "kind=env&index=1", want: "env index 1 is out of range"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleAgentStacksRoute(rec, httptest.NewRequest(http.MethodGet,
				"/api/stacks/"+stack.ID+"/file?agent="+agentRec.ID+"&"+tc.query, nil))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal() error = %v (body=%s)", err, rec.Body.String())
			}
			if body["error"] != tc.want {
				t.Fatalf("error = %v, want %q", body["error"], tc.want)
			}
		})
	}
}

func TestAgentStackFileRoutesRejectOtherMethodsAndSuffixes(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	agentRec, _, err := srv.AgentStore.Create("file-routes")
	if err != nil {
		t.Fatalf("AgentStore.Create() error = %v", err)
	}
	stack := saveAgentHostedStack(t, srv, agentRec.ID)

	tests := []struct {
		name   string
		method string
		suffix string
		want   int
	}{
		{name: "PUT on the listing", method: http.MethodPut, suffix: "/files", want: http.StatusMethodNotAllowed},
		{name: "DELETE on the listing", method: http.MethodDelete, suffix: "/files", want: http.StatusMethodNotAllowed},
		{name: "suffix after the listing", method: http.MethodGet, suffix: "/files/extra", want: http.StatusNotFound},
		{name: "POST on the file route", method: http.MethodPost, suffix: "/file", want: http.StatusMethodNotAllowed},
		{name: "GET on the draft check", method: http.MethodGet, suffix: "/file/validate", want: http.StatusMethodNotAllowed},
		{name: "suffix after the draft check", method: http.MethodPost, suffix: "/file/validate/extra", want: http.StatusNotFound},
		{name: "unknown subroute", method: http.MethodGet, suffix: "/whatever", want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleAgentStacksRoute(rec, httptest.NewRequest(tc.method,
				"/api/stacks/"+stack.ID+tc.suffix+"?agent="+agentRec.ID,
				strings.NewReader(`{"content":"services: {}\n"}`)))

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestAgentStackFileRoutesStayFailClosedWithoutTheAgentParameter pins Phase 1's
// guard: a file route for an agent-hosted stack with no agent parameter keeps
// returning 501, so it is never resolved against this server's filesystem, while
// the same route with the parameter reaches the proxy. The two paths stay
// distinct.
func TestAgentStackFileRoutesStayFailClosedWithoutTheAgentParameter(t *testing.T) {
	srv, conn, ctx, stack, agentID := newAgentFileProxyFixture(t, "file-guard")

	tests := []struct {
		name   string
		method string
		suffix string
	}{
		{name: "list", method: http.MethodGet, suffix: "/files"},
		{name: "read", method: http.MethodGet, suffix: "/file?kind=compose&index=0"},
		{name: "validate", method: http.MethodPost, suffix: "/file/validate?kind=compose&index=0"},
		{name: "write", method: http.MethodPut, suffix: "/file?kind=compose&index=0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleStackByID(rec, httptest.NewRequest(tc.method,
				"/api/stacks/"+stack.ID+tc.suffix,
				strings.NewReader(`{"content":"services: {}\n"}`)))

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}

	// The same listing with the agent parameter is proxied, so the 501 is the
	// absence of the agent rather than a second code path for the file routes.
	rec := agentFileRoundTrip(t, srv, conn, ctx,
		httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/files?agent="+agentID, nil),
		agent.TypeStackFileList,
		func(t *testing.T, request agent.Envelope) agent.ResultData {
			value, err := json.Marshal(map[string]any{"files": []stacks.FileTarget{
				agentFileTargetValue(stacks.FileKindCompose, 0, "compose.yaml", agentFileComposePath, 21),
			}})
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			return agent.ResultData{Value: value}
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("status with the agent parameter = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestAgentStackFileOperationForAnOfflineAgentIsServiceUnavailable(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	agentRec, _, err := srv.AgentStore.Create("file-offline")
	if err != nil {
		t.Fatalf("AgentStore.Create() error = %v", err)
	}
	stack := saveAgentHostedStack(t, srv, agentRec.ID)

	rec := httptest.NewRecorder()
	srv.handleAgentStacksRoute(rec, httptest.NewRequest(http.MethodGet,
		"/api/stacks/"+stack.ID+"/files?agent="+agentRec.ID, nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
}
