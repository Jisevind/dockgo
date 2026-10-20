package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"dockgo/agent"
	"dockgo/api"
	"dockgo/stacks"

	"github.com/coder/websocket"
)

func TestBuildStackOverviewsAggregatesMembers(t *testing.T) {
	web := stacks.Stack{
		ID:                "s1",
		Name:              "web",
		ProjectName:       "web",
		Kind:              stacks.KindComposeFiles,
		WorkingDir:        "/compose/web",
		ManagedContainers: []string{"c1"},
	}
	db := stacks.Stack{
		ID:          "s2",
		Name:        "db",
		ProjectName: "db",
		Kind:        stacks.KindGitRepo,
	}
	offline := stacks.Stack{
		ID:          "s3",
		Name:        "offline",
		ProjectName: "offline",
		Kind:        stacks.KindComposeFile,
		WorkingDir:  "/compose/offline",
	}

	containers := []api.ContainerOverview{
		{
			ID:             "c1",
			Name:           "web-app",
			State:          "running",
			ComposeProject: "web",
			CPUPercent:     1.5,
			MemoryUsed:     100,
			MemoryLimit:    1000,
			NetRx:          10,
			NetTx:          20,
			DiskRead:       30,
			DiskWrite:      40,
			Networks:       []string{"web_default", "shared"},
			Volumes:        []string{"web_data"},
		},
		{
			ID:             "c2",
			Name:           "db-old",
			State:          "exited",
			ComposeProject: "db",
			Networks:       []string{"db_default"},
			Volumes:        []string{"db_data"},
		},
		{
			ID:             "c3",
			Name:           "db",
			State:          "running",
			ComposeProject: "db",
			CPUPercent:     0.5,
			MemoryUsed:     200,
			MemoryLimit:    1000,
			NetRx:          5,
			NetTx:          6,
			DiskRead:       7,
			DiskWrite:      8,
			Networks:       []string{"db_default", "shared"},
			Volumes:        []string{"db_data", "shared_data"},
		},
		{
			ID:             "c4",
			Name:           "unrelated",
			State:          "running",
			ComposeProject: "other",
		},
	}

	got := buildStackOverviews([]stacks.Stack{web, db, offline}, containers)

	if len(got) != 3 {
		t.Fatalf("got %d stacks, want 3", len(got))
	}
	if got[0].Name != "db" || got[1].Name != "offline" || got[2].Name != "web" {
		t.Fatalf("stack order = %q/%q/%q, want db/offline/web",
			got[0].Name, got[1].Name, got[2].Name)
	}

	dbRow := got[0]
	if dbRow.Status != "running" || dbRow.Containers != 2 || dbRow.Running != 1 || dbRow.Stopped != 1 {
		t.Errorf("db status/counts = %q %d/%d/%d, want running 2/1/1",
			dbRow.Status, dbRow.Containers, dbRow.Running, dbRow.Stopped)
	}
	if dbRow.CPUPercent != 0.5 || dbRow.MemoryUsed != 200 || dbRow.MemoryLimit != 1000 ||
		dbRow.NetRx != 5 || dbRow.NetTx != 6 || dbRow.DiskRead != 7 || dbRow.DiskWrite != 8 {
		t.Errorf("db aggregate stats = %#v", dbRow)
	}
	if dbRow.Networks != 2 || dbRow.Volumes != 2 {
		t.Errorf("db networks/volumes = %d/%d, want 2/2", dbRow.Networks, dbRow.Volumes)
	}
	if dbRow.Source != "Git repo" || dbRow.Location != "Not set" {
		t.Errorf("db source/location = %q/%q", dbRow.Source, dbRow.Location)
	}
	if names := overviewNames(dbRow.Members); !reflect.DeepEqual(names, []string{"db", "db-old"}) {
		t.Errorf("db members = %v, want [db db-old]", names)
	}

	offlineRow := got[1]
	if offlineRow.Status != "unknown" || offlineRow.Containers != 0 || len(offlineRow.Members) != 0 {
		t.Errorf("offline row = %#v, want unknown with no members", offlineRow)
	}

	webRow := got[2]
	if webRow.Status != "running" || webRow.Containers != 1 || webRow.Running != 1 {
		t.Errorf("web status/counts = %q %d/%d", webRow.Status, webRow.Containers, webRow.Running)
	}
	if webRow.Source != "Compose files" || webRow.Location != "/compose/web" {
		t.Errorf("web source/location = %q/%q", webRow.Source, webRow.Location)
	}
	if webRow.CPUPercent != 1.5 || webRow.Networks != 2 || webRow.Volumes != 1 {
		t.Errorf("web aggregates = %#v", webRow)
	}
}

func TestBuildStackOverviewsStoppedStatus(t *testing.T) {
	stopped := stacks.Stack{
		ID:          "s1",
		Name:        "stopped",
		ProjectName: "stopped",
		Kind:        stacks.KindComposeFile,
	}
	containers := []api.ContainerOverview{
		{ID: "c1", Name: "one", State: "exited", ComposeProject: "stopped"},
		{ID: "c2", Name: "two", State: "created", ComposeProject: "stopped"},
	}

	got := buildStackOverviews([]stacks.Stack{stopped}, containers)
	if got[0].Status != "stopped" || got[0].Running != 0 || got[0].Stopped != 2 {
		t.Fatalf("status/counts = %q %d/%d, want stopped 0/2",
			got[0].Status, got[0].Running, got[0].Stopped)
	}
}

func TestHandleStacksOverviewAgent(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)
	mux := srv.agentTestMux()

	agentRec, _, err := srv.AgentStore.Create("stack-host")
	if err != nil {
		t.Fatalf("AgentStore.Create() error = %v", err)
	}
	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:              "web",
		ProjectName:       "web",
		AgentID:           agentRec.ID,
		Kind:              stacks.KindComposeFiles,
		WorkingDir:        "/compose/web",
		ManagedContainers: []string{"c1"},
	}); err != nil {
		t.Fatalf("StackStore.Save() error = %v", err)
	}

	conn, ctx := connectTestAgent(t, srv, mux, agentRec)

	req := httptest.NewRequest(http.MethodGet, "/api/stacks/overview?agent="+agentRec.ID, nil)
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleStacksOverview(rr, req)
	}()

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(containers overview request) error = %v", err)
	}
	var reqEnv agent.Envelope
	if err := json.Unmarshal(data, &reqEnv); err != nil {
		t.Fatalf("request envelope unmarshal error = %v", err)
	}
	if reqEnv.Type != agent.TypeContainersOverview {
		t.Fatalf("request type = %q, want %q", reqEnv.Type, agent.TypeContainersOverview)
	}

	payload := `[{"id":"c1","name":"web-app","state":"running","compose_project":"web","cpu_percent":1.5,"networks":["web_default"],"volumes":["web_data"]}]`
	reply, _ := agent.NewEnvelope(agent.TypeResult, reqEnv.RequestID, agent.ResultData{
		Value: json.RawMessage(payload),
	})
	replyBytes, _ := reply.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		t.Fatalf("conn.Write(containers overview result) error = %v", err)
	}

	<-done

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var rows []api.StackOverview
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("response unmarshal error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d stacks, want 1", len(rows))
	}
	if rows[0].Name != "web" || rows[0].Status != "running" ||
		rows[0].Running != 1 || rows[0].Networks != 1 || rows[0].Volumes != 1 {
		t.Fatalf("stack row = %#v", rows[0])
	}
}

func overviewNames(rows []api.ContainerOverview) []string {
	names := make([]string, len(rows))
	for i, row := range rows {
		names[i] = row.Name
	}
	return names
}
