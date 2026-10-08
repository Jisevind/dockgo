package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"dockgo/agent"

	"github.com/coder/websocket"
)

func TestNotifyAgentsOfShutdownTellsEveryAgent(t *testing.T) {
	srv := newAgentTestServer(t)
	wsURL := startAgentTestServer(t, srv)

	const agents = 2
	conns := make([]*websocket.Conn, 0, agents)
	for i := 0; i < agents; i++ {
		name := fmt.Sprintf("shutdown-host-%d", i)
		rec, key, err := srv.AgentStore.Create(name)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		conn := dialAgentWS(t, wsURL)
		reply := registerAgent(t, conn, agent.RegisterRequest{
			Key:      key,
			AgentID:  rec.ID,
			Hostname: name,
			Version:  "test",
			Name:     name,
		})
		if reply.Type != agent.TypeWelcome {
			t.Fatalf("register reply = %q, want %q", reply.Type, agent.TypeWelcome)
		}
		conns = append(conns, conn)
	}

	// Agents are always reading, and the close handshake only completes once the
	// peer has read the close frame, so read concurrently with the broadcast —
	// exactly as a real agent's read loop does.
	type agentRead struct {
		envs []agent.Envelope
		err  error
	}
	reads := make([]chan agentRead, agents)
	for i, conn := range conns {
		ch := make(chan agentRead, 1)
		reads[i] = ch
		go func(conn *websocket.Conn, ch chan<- agentRead) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var envs []agent.Envelope
			for {
				_, data, err := conn.Read(ctx)
				if err != nil {
					ch <- agentRead{envs: envs, err: err}
					return
				}
				var env agent.Envelope
				if err := json.Unmarshal(data, &env); err != nil {
					ch <- agentRead{envs: envs, err: err}
					return
				}
				envs = append(envs, env)
			}
		}(conn, ch)
	}

	if got := srv.notifyAgentsOfShutdown(); got != agents {
		t.Fatalf("notifyAgentsOfShutdown() = %d, want %d", got, agents)
	}

	// Every agent must be told before its channel closes, rather than left to
	// discover a dead socket.
	for i, ch := range reads {
		r := <-ch
		if len(r.envs) != 1 || r.envs[0].Type != agent.TypeDisconnect {
			t.Fatalf("agent-%d received %+v (read err %v), want a single %q envelope",
				i, r.envs, r.err, agent.TypeDisconnect)
		}
	}

	// The registry must be cleared, not left claiming channels that are closed.
	if ids := srv.AgentManager.OnlineIDs(); len(ids) != 0 {
		t.Fatalf("OnlineIDs() = %v, want none after the shutdown broadcast", ids)
	}
}

func TestNotifyAgentsOfShutdownWithNoAgents(t *testing.T) {
	srv := newAgentTestServer(t)

	if got := srv.notifyAgentsOfShutdown(); got != 0 {
		t.Fatalf("notifyAgentsOfShutdown() = %d, want 0", got)
	}
}
