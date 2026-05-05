package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"fawkes/pkg/structs"
)

const httpxTestPayloadUUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

// newHTTPXTestProfile creates an HTTPXProfile pointed at the given test server.
// Uses body message placement and no transforms for simplicity.
func newHTTPXTestProfile(ts *httptest.Server) *HTTPXProfile {
	verbCfg := VerbConfig{
		Verb: "POST",
		URIs: []string{"/agent"},
		Client: ClientConfig{
			Message: MessageConfig{Location: "body"},
		},
	}
	return &HTTPXProfile{
		Domains:        []string{ts.URL},
		DomainRotation: "fail-over",
		Config: &AgentConfig{
			Get:  verbCfg,
			Post: verbCfg,
		},
		client: ts.Client(),
	}
}

// --- GetTasking hook routing tests ---

func TestHTTPXGetTasking_HandleDelegatesCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"delegates": []map[string]interface{}{
				{"message": "bXNnMQ==", "uuid": "child-uuid-httpx-001", "c2_profile": "tcp"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	var gotDelegates []structs.DelegateMessage
	profile.HandleDelegates = func(d []structs.DelegateMessage) { gotDelegates = d }

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if len(gotDelegates) != 1 {
		t.Fatalf("HandleDelegates called with %d items, want 1", len(gotDelegates))
	}
	if gotDelegates[0].UUID != "child-uuid-httpx-001" {
		t.Errorf("delegate UUID = %q, want child-uuid-httpx-001", gotDelegates[0].UUID)
	}
}

func TestHTTPXGetTasking_HandleRpfwdCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"rpfwd": []map[string]interface{}{
				{"server_id": 77, "data": "cnBmd2hYdHg=", "exit": false},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	var gotRpfwd []structs.SocksMsg
	profile.HandleRpfwd = func(msgs []structs.SocksMsg) { gotRpfwd = msgs }

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if len(gotRpfwd) != 1 {
		t.Fatalf("HandleRpfwd called with %d items, want 1", len(gotRpfwd))
	}
	if gotRpfwd[0].ServerId != 77 {
		t.Errorf("rpfwd ServerId = %d, want 77", gotRpfwd[0].ServerId)
	}
}

func TestHTTPXGetTasking_HandleInteractiveCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"interactive": []map[string]interface{}{
				{"task_id": "task-pty-httpx-001", "data": "aW5wdXQ=", "message_type": 0},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	var gotInteractive []structs.InteractiveMsg
	profile.HandleInteractive = func(msgs []structs.InteractiveMsg) { gotInteractive = msgs }

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if len(gotInteractive) != 1 {
		t.Fatalf("HandleInteractive called with %d items, want 1", len(gotInteractive))
	}
	if gotInteractive[0].TaskID != "task-pty-httpx-001" {
		t.Errorf("interactive TaskID = %q, want task-pty-httpx-001", gotInteractive[0].TaskID)
	}
}

func TestHTTPXGetTasking_GetDelegatesOnlyCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"action": "get_tasking"})
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	called := false
	profile.GetDelegatesOnly = func() []structs.DelegateMessage {
		called = true
		return []structs.DelegateMessage{
			{Message: "bXNn", UUID: "child-outbound-httpx", C2ProfileName: "tcp"},
		}
	}

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	if _, _, err := profile.GetTasking(agent, nil); err != nil {
		t.Fatalf("GetTasking returned error: %v", err)
	}
	if !called {
		t.Error("GetDelegatesOnly should be called to collect outbound delegate messages")
	}
}

// --- PostResponse hook routing tests ---

func TestHTTPXPostResponse_GetDelegatesAndEdgesCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	called := false
	profile.GetDelegatesAndEdges = func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
		called = true
		return []structs.DelegateMessage{
			{Message: "bXNnMg==", UUID: "child-uuid-httpx-002", C2ProfileName: "tcp"},
		}, nil
	}

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	resp := structs.Response{TaskID: "httpx-task-001", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if !called {
		t.Error("GetDelegatesAndEdges hook was not called")
	}
}

func TestHTTPXPostResponse_GetRpfwdOutboundCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	called := false
	profile.GetRpfwdOutbound = func() []structs.SocksMsg {
		called = true
		return []structs.SocksMsg{{ServerId: 88, Data: "cnBmd2RhdGE=", Exit: false}}
	}

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	resp := structs.Response{TaskID: "httpx-task-002", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if !called {
		t.Error("GetRpfwdOutbound hook was not called")
	}
}

func TestHTTPXPostResponse_GetInteractiveOutboundCalled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	called := false
	profile.GetInteractiveOutbound = func() []structs.InteractiveMsg {
		called = true
		return []structs.InteractiveMsg{
			{TaskID: "task-pty-httpx-out", Data: "b3V0cHV0", MessageType: structs.InteractiveOutput},
		}
	}

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	resp := structs.Response{TaskID: "httpx-task-003", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if !called {
		t.Error("GetInteractiveOutbound hook was not called")
	}
}

func TestHTTPXPostResponse_RoutesDelegatesFromServerResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"delegates": []map[string]interface{}{
				{"message": "Y2hpbGRtc2c=", "uuid": "child-httpx-003", "c2_profile": "tcp"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	var gotDelegates []structs.DelegateMessage
	profile.HandleDelegates = func(d []structs.DelegateMessage) { gotDelegates = d }

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	resp := structs.Response{TaskID: "httpx-task-004", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if len(gotDelegates) != 1 {
		t.Fatalf("HandleDelegates called with %d items, want 1", len(gotDelegates))
	}
	if gotDelegates[0].UUID != "child-httpx-003" {
		t.Errorf("delegate UUID = %q, want child-httpx-003", gotDelegates[0].UUID)
	}
}

func TestHTTPXPostResponse_RoutesRpfwdFromServerResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"rpfwd": []map[string]interface{}{
				{"server_id": 66, "data": "cnBmd3Jlc3A=", "exit": false},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	var gotRpfwd []structs.SocksMsg
	profile.HandleRpfwd = func(msgs []structs.SocksMsg) { gotRpfwd = msgs }

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	resp := structs.Response{TaskID: "httpx-task-005", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if len(gotRpfwd) != 1 {
		t.Fatalf("HandleRpfwd called with %d items, want 1", len(gotRpfwd))
	}
	if gotRpfwd[0].ServerId != 66 {
		t.Errorf("rpfwd ServerId = %d, want 66", gotRpfwd[0].ServerId)
	}
}

func TestHTTPXPostResponse_RoutesInteractiveFromServerResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"interactive": []map[string]interface{}{
				{"task_id": "task-pty-httpx-resp", "data": "b3V0cHV0", "message_type": 1},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := newHTTPXTestProfile(ts)
	var gotInteractive []structs.InteractiveMsg
	profile.HandleInteractive = func(msgs []structs.InteractiveMsg) { gotInteractive = msgs }

	agent := &structs.Agent{PayloadUUID: httpxTestPayloadUUID}
	resp := structs.Response{TaskID: "httpx-task-006", Completed: true}
	if _, err := profile.PostResponse(resp, agent, nil); err != nil {
		t.Fatalf("PostResponse returned error: %v", err)
	}
	if len(gotInteractive) != 1 {
		t.Fatalf("HandleInteractive called with %d items, want 1", len(gotInteractive))
	}
	if gotInteractive[0].TaskID != "task-pty-httpx-resp" {
		t.Errorf("interactive TaskID = %q, want task-pty-httpx-resp", gotInteractive[0].TaskID)
	}
}
