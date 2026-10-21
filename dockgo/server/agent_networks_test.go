package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dockgo/agent"

	"github.com/coder/websocket"
)

// testAgentListDispatch verifies a list endpoint proxies the request to the
// selected agent and returns its result unchanged.
func testAgentListDispatch(t *testing.T, route, msgType, payload string, handler func(*Server, http.ResponseWriter, *http.Request)) {
	t.Helper()

	srv, _ := newTestServerWithAgent(t)
	mux := srv.agentTestMux()

	agentRec, _, err := srv.AgentStore.Create("list-host")
	if err != nil {
		t.Fatalf("AgentStore.Create() error = %v", err)
	}

	conn, ctx := connectTestAgent(t, srv, mux, agentRec)

	req := httptest.NewRequest(http.MethodGet, route+"?agent="+agentRec.ID, nil)
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(srv, rr, req)
	}()

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(%s request) error = %v", msgType, err)
	}
	var reqEnv agent.Envelope
	if err := json.Unmarshal(data, &reqEnv); err != nil {
		t.Fatalf("request envelope unmarshal error = %v", err)
	}
	if reqEnv.Type != msgType {
		t.Fatalf("request type = %q, want %q", reqEnv.Type, msgType)
	}

	reply, _ := agent.NewEnvelope(agent.TypeResult, reqEnv.RequestID, agent.ResultData{
		Value: json.RawMessage(payload),
	})
	replyBytes, _ := reply.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		t.Fatalf("conn.Write(%s result) error = %v", msgType, err)
	}

	<-done

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rr.Body.String(); got != payload {
		t.Errorf("body = %s, want %s", got, payload)
	}
}

func TestAgentContainersOverviewDispatch(t *testing.T) {
	testAgentListDispatch(t,
		"/api/containers/overview",
		agent.TypeContainersOverview,
		`[{"id":"abc","name":"web","image":"nginx:latest","state":"running","health":"healthy","uptime_seconds":7200,"restart_count":0,"cpu_percent":1.5,"memory_used":100,"memory_limit":200,"net_rx":10,"net_tx":20,"disk_read":30,"disk_write":40,"ip":"172.17.0.2","ports":["8080:80"],"compose_project":"web"}]`,
		(*Server).handleContainersOverview,
	)
}

func TestAgentNetworkDetailDispatch(t *testing.T) {
	testAgentListDispatch(t,
		"/api/networks/web_default",
		agent.TypeNetworkInspect,
		`{"id":"n1","name":"web_default","driver":"bridge","scope":"local","subnets":["172.20.0.0/16"],"gateways":["172.20.0.1"],"built_in":false,"containers":[{"id":"c1","name":"web-app","ipv4_address":"172.20.0.2","ipv6_address":"","stack":"web"}],"stacks":["web"]}`,
		(*Server).handleNetworkByID,
	)
}

func TestAgentNetworksDispatch(t *testing.T) {
	testAgentListDispatch(t,
		"/api/networks",
		agent.TypeNetworksList,
		`[{"id":"n1","name":"bridge","driver":"bridge","scope":"local","subnets":["172.17.0.0/16"],"gateways":["172.17.0.1"],"containers":0,"built_in":true}]`,
		(*Server).handleNetworks,
	)
}

func TestAgentImagesDispatch(t *testing.T) {
	testAgentListDispatch(t,
		"/api/images",
		agent.TypeImagesList,
		`[{"id":"sha256:aaa","repository":"nginx","tag":"latest","created":100,"size":1000,"containers":2}]`,
		(*Server).handleImages,
	)
}

func TestAgentVolumesDispatch(t *testing.T) {
	testAgentListDispatch(t,
		"/api/volumes",
		agent.TypeVolumesList,
		`[{"name":"data","driver":"local","scope":"local","mountpoint":"/var/lib/docker/volumes/data/_data","created_at":"2024-01-01T00:00:00Z","containers":2,"stacks":["web"],"used_by":["app","db"]}]`,
		(*Server).handleVolumes,
	)
}

func TestAgentVolumeDetailDispatch(t *testing.T) {
	testAgentListDispatch(t,
		"/api/volumes/data",
		agent.TypeVolumeInspect,
		`{"name":"data","driver":"local","scope":"local","mountpoint":"/var/lib/docker/volumes/data/_data","created_at":"2024-01-01T00:00:00Z","labels":{},"stacks":[],"containers":[]}`,
		(*Server).handleVolumeByID,
	)
}
