package agent

import (
	"encoding/json"
	"testing"
	"time"

	"dockgo/stacks"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	env, err := NewEnvelope(TypeContainersList, "req-123", ScanRequest{Force: true})
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.Type != TypeContainersList {
		t.Errorf("type = %q, want %q", env.Type, TypeContainersList)
	}
	if env.RequestID != "req-123" {
		t.Errorf("request_id = %q, want %q", env.RequestID, "req-123")
	}

	data, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back Envelope
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	var req ScanRequest
	if err := back.Decode(&req); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !req.Force {
		t.Errorf("force = false, want true")
	}
}

func TestEnvelopeDecodeNilData(t *testing.T) {
	env := Envelope{Type: TypeHeartbeat}
	var dst struct{ X string }
	if err := env.Decode(&dst); err != nil {
		t.Fatalf("Decode on empty data should be a no-op: %v", err)
	}
}

func TestNewEnvelopeMarshalError(t *testing.T) {
	_, err := NewEnvelope(TypeContainersList, "r", make(chan int))
	if err == nil {
		t.Fatalf("expected marshal error for unencodable payload")
	}
}

func TestRegisterRequestJWTRoundTrip(t *testing.T) {
	req := RegisterRequest{
		Key:      "",
		JWT:      "eyJhbGciOiJIUzI1NiJ9.token",
		Hostname: "host-a",
		Version:  "v1",
		AgentID:  "ag-1",
		Name:     "agent-one",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back RegisterRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.JWT != req.JWT {
		t.Errorf("jwt = %q, want %q", back.JWT, req.JWT)
	}
	if back.Key != "" {
		t.Errorf("key should be omitted on JWT reconnect, got %q", back.Key)
	}
}

func TestProgressResultPayloads(t *testing.T) {
	progress := ProgressData{
		ProgressType: ProgressScan,
		Line:         "Pulling image",
	}
	env, err := NewEnvelope(TypeProgress, "rid", progress)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	var pd ProgressData
	if err := env.Decode(&pd); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if pd.ProgressType != ProgressScan || pd.Line != progress.Line {
		t.Errorf("progress round-trip mismatch: %+v", pd)
	}

	result := ResultData{Error: "boom"}
	env2, _ := NewEnvelope(TypeResult, "rid", result)
	var rd ResultData
	if err := env2.Decode(&rd); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if rd.Error != "boom" {
		t.Errorf("error = %q, want %q", rd.Error, "boom")
	}
}

func TestServerStatsData(t *testing.T) {
	stats := ServerStatsData{
		CPUPercent: 12.5,
		RAMUsed:    64,
		RAMTotal:   128,
		DiskUsed:   500,
		DiskTotal:  1000,
	}
	env, _ := NewEnvelope(TypeResult, "rid", stats)
	var back ServerStatsData
	if err := env.Decode(&back); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if back.CPUPercent != 12.5 || back.RAMUsed != 64 || back.RAMTotal != 128 ||
		back.DiskUsed != 500 || back.DiskTotal != 1000 {
		t.Errorf("stats round-trip mismatch: %+v", back)
	}
}

func TestOpTimeout(t *testing.T) {
	cases := []struct {
		msgType string
		min     time.Duration
	}{
		{TypeContainersList, 2 * time.Minute},
		{TypeServerStats, 2 * time.Minute},
		{TypeUpdate, 10 * time.Minute},
		{TypeStackAction, 10 * time.Minute},
		{TypeScan, 15 * time.Minute},
		{TypeContainerLogs, 10 * time.Minute},
		{TypeStackValidate, 5 * time.Minute},
		{TypeStackContainers, 5 * time.Minute},
		{TypeStackDiscover, 5 * time.Minute},
	}
	for _, tc := range cases {
		if got := opTimeout(tc.msgType); got < tc.min {
			t.Errorf("opTimeout(%q) = %v, want >= %v", tc.msgType, got, tc.min)
		}
	}
}

func TestStreamWriter(t *testing.T) {
	var lines []string
	sw := stacks.NewStreamWriter(func(l string) { lines = append(lines, l) })

	_, _ = sw.Write([]byte("line1\nline2\r\npartial"))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(lines), lines)
	}
	if lines[0] != "line1" || lines[1] != "line2" {
		t.Errorf("lines = %v", lines)
	}

	_, _ = sw.Write([]byte(" rest\n"))
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %v", len(lines), lines)
	}
	if lines[2] != "partial rest" {
		t.Errorf("line = %q, want %q", lines[2], "partial rest")
	}
}

func TestStreamWriterEmptyLines(t *testing.T) {
	var lines []string
	sw := stacks.NewStreamWriter(func(l string) { lines = append(lines, l) })

	_, _ = sw.Write([]byte("\n\n"))
	if len(lines) != 2 || lines[0] != "" || lines[1] != "" {
		t.Errorf("empty lines not emitted: %v", lines)
	}
}
