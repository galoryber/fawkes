package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// --- buildWQLTrigger ---

func TestBuildWQLTrigger_Logon(t *testing.T) {
	query, err := buildWQLTrigger("logon", 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "Win32_LogonSession") {
		t.Errorf("expected Win32_LogonSession in query, got %s", query)
	}
	if !strings.Contains(query, "__InstanceCreationEvent") {
		t.Errorf("expected __InstanceCreationEvent in query, got %s", query)
	}
}

func TestBuildWQLTrigger_Startup(t *testing.T) {
	query, err := buildWQLTrigger("startup", 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "Win32_PerfFormattedData_PerfOS_System") {
		t.Errorf("expected PerfOS_System in query, got %s", query)
	}
	if !strings.Contains(query, "SystemUpTime") {
		t.Errorf("expected SystemUpTime in query, got %s", query)
	}
}

func TestBuildWQLTrigger_Interval(t *testing.T) {
	query, err := buildWQLTrigger("interval", 60, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "__TimerEvent") {
		t.Errorf("expected __TimerEvent in query, got %s", query)
	}
	if !strings.Contains(query, "PerfDataTimer") {
		t.Errorf("expected PerfDataTimer in query, got %s", query)
	}
}

func TestBuildWQLTrigger_Process(t *testing.T) {
	query, err := buildWQLTrigger("process", 0, "notepad.exe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "notepad.exe") {
		t.Errorf("expected notepad.exe in query, got %s", query)
	}
	if !strings.Contains(query, "Win32_Process") {
		t.Errorf("expected Win32_Process in query, got %s", query)
	}
}

func TestBuildWQLTrigger_ProcessMissingName(t *testing.T) {
	_, err := buildWQLTrigger("process", 0, "")
	if err == nil {
		t.Error("expected error for process trigger without process_name")
	}
	if !strings.Contains(err.Error(), "process_name required") {
		t.Errorf("expected 'process_name required' error, got: %v", err)
	}
}

func TestBuildWQLTrigger_UnknownTrigger(t *testing.T) {
	_, err := buildWQLTrigger("invalid", 0, "")
	if err == nil {
		t.Error("expected error for unknown trigger")
	}
	if !strings.Contains(err.Error(), "unknown trigger") {
		t.Errorf("expected 'unknown trigger' error, got: %v", err)
	}
}

func TestBuildWQLTrigger_CaseInsensitive(t *testing.T) {
	tests := []string{"LOGON", "Logon", "logon", "Startup", "STARTUP", "INTERVAL", "PROCESS"}
	processNames := map[string]string{"PROCESS": "test.exe"}

	for _, trigger := range tests {
		pname := processNames[trigger]
		_, err := buildWQLTrigger(trigger, 60, pname)
		if err != nil {
			t.Errorf("buildWQLTrigger(%q) failed: %v", trigger, err)
		}
	}
}

// --- parseWmiPersistArgs ---

func TestParseWmiPersistArgs_ValidJSON(t *testing.T) {
	task := structs.Task{
		Params: `{"action":"install","name":"test","command":"calc.exe","trigger":"logon"}`,
	}
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		t.Fatalf("unexpected error result: %s", errResult.Output)
	}
	if args.Action != "install" {
		t.Errorf("expected action=install, got %s", args.Action)
	}
	if args.Name != "test" {
		t.Errorf("expected name=test, got %s", args.Name)
	}
	if args.Command != "calc.exe" {
		t.Errorf("expected command=calc.exe, got %s", args.Command)
	}
	if args.Trigger != "logon" {
		t.Errorf("expected trigger=logon, got %s", args.Trigger)
	}
}

func TestParseWmiPersistArgs_EmptyParams(t *testing.T) {
	task := structs.Task{Params: ""}
	_, errResult := parseWmiPersistArgs(task)
	if errResult == nil {
		t.Fatal("expected error for empty params")
		return
	}
	if errResult.Status != "error" {
		t.Errorf("expected error status, got %s", errResult.Status)
	}
	if !strings.Contains(errResult.Output, "parameters required") {
		t.Errorf("expected 'parameters required' message, got: %s", errResult.Output)
	}
}

func TestParseWmiPersistArgs_InvalidJSON(t *testing.T) {
	task := structs.Task{Params: "not json at all"}
	_, errResult := parseWmiPersistArgs(task)
	if errResult == nil {
		t.Fatal("expected error for invalid JSON")
		return
	}
	if errResult.Status != "error" {
		t.Errorf("expected error status, got %s", errResult.Status)
	}
	if !strings.Contains(errResult.Output, "Error parsing") {
		t.Errorf("expected 'Error parsing' message, got: %s", errResult.Output)
	}
}

func TestParseWmiPersistArgs_ProcessTrigger(t *testing.T) {
	task := structs.Task{
		Params: `{"action":"install","name":"watcher","command":"payload.exe","trigger":"process","process_name":"explorer.exe","interval_sec":30}`,
	}
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if args.ProcessName != "explorer.exe" {
		t.Errorf("expected process_name=explorer.exe, got %s", args.ProcessName)
	}
	if args.IntervalSec != 30 {
		t.Errorf("expected interval_sec=30, got %d", args.IntervalSec)
	}
}

func TestParseWmiPersistArgs_AllFields(t *testing.T) {
	task := structs.Task{
		Params: `{"action":"remove","name":"subscription","command":"cmd.exe","trigger":"interval","interval_sec":300,"process_name":"svchost.exe","target":"\\\\dc01"}`,
	}
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if args.Action != "remove" || args.Name != "subscription" || args.Target != `\\dc01` {
		t.Errorf("unexpected args: %+v", args)
	}
}

// --- isScriptConsumer ---

func TestIsScriptConsumer_Script(t *testing.T) {
	args := wmiPersistArgs{ConsumerType: "script"}
	if !args.isScriptConsumer() {
		t.Error("expected isScriptConsumer=true for consumer_type=script")
	}
}

func TestIsScriptConsumer_ScriptCaseInsensitive(t *testing.T) {
	args := wmiPersistArgs{ConsumerType: "Script"}
	if !args.isScriptConsumer() {
		t.Error("expected isScriptConsumer=true for consumer_type=Script")
	}
}

func TestIsScriptConsumer_Command(t *testing.T) {
	args := wmiPersistArgs{ConsumerType: "command"}
	if args.isScriptConsumer() {
		t.Error("expected isScriptConsumer=false for consumer_type=command")
	}
}

func TestIsScriptConsumer_Empty(t *testing.T) {
	args := wmiPersistArgs{}
	if args.isScriptConsumer() {
		t.Error("expected isScriptConsumer=false for empty consumer_type")
	}
}

// --- resolvedScriptEngine ---

func TestResolvedScriptEngine_Default(t *testing.T) {
	args := wmiPersistArgs{}
	if args.resolvedScriptEngine() != "VBScript" {
		t.Errorf("expected VBScript default, got %s", args.resolvedScriptEngine())
	}
}

func TestResolvedScriptEngine_JScript(t *testing.T) {
	args := wmiPersistArgs{ScriptEngine: "jscript"}
	if args.resolvedScriptEngine() != "JScript" {
		t.Errorf("expected JScript, got %s", args.resolvedScriptEngine())
	}
}

func TestResolvedScriptEngine_VBScript(t *testing.T) {
	args := wmiPersistArgs{ScriptEngine: "VBScript"}
	if args.resolvedScriptEngine() != "VBScript" {
		t.Errorf("expected VBScript, got %s", args.resolvedScriptEngine())
	}
}

// --- consumerClassName ---

func TestConsumerClassName_Default(t *testing.T) {
	args := wmiPersistArgs{}
	if args.consumerClassName() != "CommandLineEventConsumer" {
		t.Errorf("expected CommandLineEventConsumer, got %s", args.consumerClassName())
	}
}

func TestConsumerClassName_Script(t *testing.T) {
	args := wmiPersistArgs{ConsumerType: "script"}
	if args.consumerClassName() != "ActiveScriptEventConsumer" {
		t.Errorf("expected ActiveScriptEventConsumer, got %s", args.consumerClassName())
	}
}

func TestConsumerClassName_Command(t *testing.T) {
	args := wmiPersistArgs{ConsumerType: "command"}
	if args.consumerClassName() != "CommandLineEventConsumer" {
		t.Errorf("expected CommandLineEventConsumer, got %s", args.consumerClassName())
	}
}

// --- parseWmiPersistArgs with new fields ---

func TestParseWmiPersistArgs_ScriptConsumer(t *testing.T) {
	task := structs.Task{
		Params: `{"action":"install","name":"scriptback","command":"Set ws = CreateObject(\"Wscript.Shell\")\nws.Run \"payload.exe\"","trigger":"logon","consumer_type":"script","script_engine":"VBScript"}`,
	}
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if !args.isScriptConsumer() {
		t.Error("expected script consumer")
	}
	if args.resolvedScriptEngine() != "VBScript" {
		t.Errorf("expected VBScript, got %s", args.resolvedScriptEngine())
	}
	if args.consumerClassName() != "ActiveScriptEventConsumer" {
		t.Errorf("expected ActiveScriptEventConsumer, got %s", args.consumerClassName())
	}
}
