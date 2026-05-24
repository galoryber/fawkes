package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"fawkes/pkg/structs"
)

// --- GetTasking delegate/rpfwd/interactive hook routing tests ---
// (Basic tasking flows are in http_integration_test.go)

func TestGetTasking_HandleDelegatesCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"delegates": []map[string]interface{}{
				{"message": "bXNnMQ==", "uuid": "child-uuid-001", "c2_profile": "tcp"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	var gotDelegates []structs.DelegateMessage
	profile.HandleDelegates = func(d []structs.DelegateMessage) { gotDelegates = d }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if len(gotDelegates) != 1 {
		t.Fatalf("HandleDelegates called with %d items, want 1", len(gotDelegates))
	}
	if gotDelegates[0].UUID != "child-uuid-001" {
		t.Errorf("delegate UUID = %q, want child-uuid-001", gotDelegates[0].UUID)
	}
}

func TestGetTasking_HandleDelegatesNotCalledWhenEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"action": "get_tasking"})
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	called := false
	profile.HandleDelegates = func(d []structs.DelegateMessage) { called = true }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if called {
		t.Error("HandleDelegates should not be called when no delegates in response")
	}
}

func TestGetTasking_HandleRpfwdCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"rpfwd": []map[string]interface{}{
				{"server_id": 42, "data": "cnBmd2Q=", "exit": false},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	var gotRpfwd []structs.SocksMsg
	profile.HandleRpfwd = func(msgs []structs.SocksMsg) { gotRpfwd = msgs }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if len(gotRpfwd) != 1 {
		t.Fatalf("HandleRpfwd called with %d items, want 1", len(gotRpfwd))
	}
	if gotRpfwd[0].ServerId != 42 {
		t.Errorf("rpfwd ServerId = %d, want 42", gotRpfwd[0].ServerId)
	}
}

func TestGetTasking_HandleInteractiveCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"interactive": []map[string]interface{}{
				{"task_id": "task-pty-001", "data": "aW5wdXQ=", "message_type": 0},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	var gotInteractive []structs.InteractiveMsg
	profile.HandleInteractive = func(msgs []structs.InteractiveMsg) { gotInteractive = msgs }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if len(gotInteractive) != 1 {
		t.Fatalf("HandleInteractive called with %d items, want 1", len(gotInteractive))
	}
	if gotInteractive[0].TaskID != "task-pty-001" {
		t.Errorf("interactive TaskID = %q, want task-pty-001", gotInteractive[0].TaskID)
	}
}

func TestGetTasking_GetDelegatesOnlyCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"action": "get_tasking"})
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	called := false
	profile.GetDelegatesOnly = func() []structs.DelegateMessage {
		called = true
		return []structs.DelegateMessage{
			{Message: "bXNn", UUID: "child-outbound", C2ProfileName: "tcp"},
		}
	}

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if !called {
		t.Error("GetDelegatesOnly should be called to collect outbound delegate messages")
	}
}

// --- PostResponse delegate/rpfwd/interactive hook routing tests ---

func TestPostResponse_GetDelegatesAndEdgesCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	called := false
	profile.GetDelegatesAndEdges = func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
		called = true
		return []structs.DelegateMessage{
			{Message: "bXNnMg==", UUID: "child-uuid-002", C2ProfileName: "tcp"},
		}, []structs.P2PConnectionMessage{
			{Source: "parent-uuid", Destination: "child-uuid-002", Action: "add", C2ProfileName: "tcp"},
		}
	}

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	resp := structs.Response{TaskID: "task-001", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if !called {
		t.Error("GetDelegatesAndEdges hook was not called")
	}
}

func TestPostResponse_GetRpfwdOutboundCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	called := false
	profile.GetRpfwdOutbound = func() []structs.SocksMsg {
		called = true
		return []structs.SocksMsg{{ServerId: 99, Data: "cnBmd2RhdGE=", Exit: false}}
	}

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	resp := structs.Response{TaskID: "task-002", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if !called {
		t.Error("GetRpfwdOutbound hook was not called")
	}
}

func TestPostResponse_GetInteractiveOutboundCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	called := false
	profile.GetInteractiveOutbound = func() []structs.InteractiveMsg {
		called = true
		return []structs.InteractiveMsg{
			{TaskID: "task-pty-out", Data: "b3V0cHV0", MessageType: structs.InteractiveOutput},
		}
	}

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	resp := structs.Response{TaskID: "task-003", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if !called {
		t.Error("GetInteractiveOutbound hook was not called")
	}
}

func TestPostResponse_RoutesDelegatesFromServerResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"delegates": []map[string]interface{}{
				{"message": "Y2hpbGRtc2c=", "uuid": "child-uuid-003", "c2_profile": "tcp"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	var gotDelegates []structs.DelegateMessage
	profile.HandleDelegates = func(d []structs.DelegateMessage) { gotDelegates = d }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	resp := structs.Response{TaskID: "task-004", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if len(gotDelegates) != 1 {
		t.Fatalf("HandleDelegates called with %d items, want 1", len(gotDelegates))
	}
	if gotDelegates[0].UUID != "child-uuid-003" {
		t.Errorf("delegate UUID = %q, want child-uuid-003", gotDelegates[0].UUID)
	}
}

func TestPostResponse_RoutesRpfwdFromServerResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"rpfwd": []map[string]interface{}{
				{"server_id": 55, "data": "cnBmd3Jlc3A=", "exit": false},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	var gotRpfwd []structs.SocksMsg
	profile.HandleRpfwd = func(msgs []structs.SocksMsg) { gotRpfwd = msgs }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	resp := structs.Response{TaskID: "task-005", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if len(gotRpfwd) != 1 {
		t.Fatalf("HandleRpfwd called with %d items, want 1", len(gotRpfwd))
	}
	if gotRpfwd[0].ServerId != 55 {
		t.Errorf("rpfwd ServerId = %d, want 55", gotRpfwd[0].ServerId)
	}
}

func TestPostResponse_RoutesInteractiveFromServerResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"interactive": []map[string]interface{}{
				{"task_id": "task-pty-resp", "data": "b3V0cHV0", "message_type": 1},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}
	var gotInteractive []structs.InteractiveMsg
	profile.HandleInteractive = func(msgs []structs.InteractiveMsg) { gotInteractive = msgs }

	agent := &structs.Agent{PayloadUUID: testPayloadUUID}
	resp := structs.Response{TaskID: "task-006", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if len(gotInteractive) != 1 {
		t.Fatalf("HandleInteractive called with %d items, want 1", len(gotInteractive))
	}
	if gotInteractive[0].TaskID != "task-pty-resp" {
		t.Errorf("interactive TaskID = %q, want task-pty-resp", gotInteractive[0].TaskID)
	}
}
