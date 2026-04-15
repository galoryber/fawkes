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

        let pidMatch = combined.match(/Target PID:\s*(\d+)/);
        let tidMatch = combined.match(/TID:\s*(\d+)/);
        let sizeMatch = combined.match(/Shellcode size:\s*(\d+)\s*bytes/);
        let addrMatch = combined.match(/Shellcode at\s*(0x[0-9A-Fa-f]+)/);
        let stateMatch = combined.match(/thread state:\s*(.+)/);
        let syscallMatch = combined.match(/Using indirect syscalls/);
        let success = combined.includes("completed successfully") || combined.includes("queued successfully");

        let headers = [
            {"plaintext": "Property", "type": "string", "width": 140},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [
            {"Property": {"plaintext": "Technique"}, "Value": {"plaintext": "APC Injection", "cellStyle": {"fontWeight": "bold"}}, "rowStyle": {}},
            {"Property": {"plaintext": "Status"}, "Value": {"plaintext": success ? "SUCCESS" : "FAILED", "cellStyle": {"fontWeight": "bold", "color": success ? "#4CAF50" : "#f44336"}}, "rowStyle": {"backgroundColor": success ? "rgba(76,175,80,0.1)" : "rgba(244,67,54,0.1)"}},
        ];
        if(pidMatch) rows.push({"Property": {"plaintext": "Target PID"}, "Value": {"plaintext": pidMatch[1], "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(tidMatch) rows.push({"Property": {"plaintext": "Target TID"}, "Value": {"plaintext": tidMatch[1], "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(sizeMatch) rows.push({"Property": {"plaintext": "Shellcode Size"}, "Value": {"plaintext": sizeMatch[1] + " bytes"}, "rowStyle": {}});
        if(addrMatch) rows.push({"Property": {"plaintext": "Remote Address"}, "Value": {"plaintext": addrMatch[1], "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(stateMatch) rows.push({"Property": {"plaintext": "Thread State"}, "Value": {"plaintext": stateMatch[1].trim()}, "rowStyle": {}});
        if(syscallMatch) rows.push({"Property": {"plaintext": "Syscalls"}, "Value": {"plaintext": "Indirect (Nt* stubs)", "cellStyle": {"color": "#4CAF50"}}, "rowStyle": {}});

        return {"table": [{"headers": headers, "rows": rows, "title": "APC Injection Result"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
