function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    try {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        combined = combined.trim();

        let pidMatch = combined.match(/Process ID \(PID\):\s*(\d+)/);
        let tidMatch = combined.match(/Thread ID \(TID\):\s*(\d+)/);
        let exeMatch = combined.match(/Target executable:\s*(.+)/);
        let ppidMatch = combined.match(/PPID spoofing: parent PID\s*(\d+)/);
        let blockDllMatch = combined.match(/BlockDLLs/i);
        let success = combined.includes("Process ID (PID):");
        let failed = combined.includes("Error:") || combined.includes("failed");

        let headers = [
            {"plaintext": "Property", "type": "string", "width": 140},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let status = failed ? "FAILED" : (success ? "SUCCESS" : "UNKNOWN");
        let statusColor = failed ? "#f44336" : (success ? "#4CAF50" : "#FF9800");
        let statusBg = failed ? "rgba(244,67,54,0.1)" : (success ? "rgba(76,175,80,0.1)" : "rgba(255,152,0,0.1)");
        let rows = [
            {"Property": {"plaintext": "Operation"}, "Value": {"plaintext": "Process Spawn", "cellStyle": {"fontWeight": "bold"}}, "rowStyle": {}},
            {"Property": {"plaintext": "Status"}, "Value": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": statusColor}}, "rowStyle": {"backgroundColor": statusBg}},
        ];
        if(exeMatch) rows.push({"Property": {"plaintext": "Executable"}, "Value": {"plaintext": exeMatch[1].trim(), "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(pidMatch) rows.push({"Property": {"plaintext": "PID"}, "Value": {"plaintext": pidMatch[1], "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontWeight": "bold"}}, "rowStyle": {}});
        if(tidMatch) rows.push({"Property": {"plaintext": "TID"}, "Value": {"plaintext": tidMatch[1], "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(ppidMatch) rows.push({"Property": {"plaintext": "PPID Spoof"}, "Value": {"plaintext": "PID " + ppidMatch[1], "cellStyle": {"color": "#FF9800"}}, "rowStyle": {}});
        if(blockDllMatch) rows.push({"Property": {"plaintext": "BlockDLLs"}, "Value": {"plaintext": "Enabled", "cellStyle": {"color": "#4CAF50"}}, "rowStyle": {}});

        return {"table": [{"headers": headers, "rows": rows, "title": "Process Spawn Result"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
