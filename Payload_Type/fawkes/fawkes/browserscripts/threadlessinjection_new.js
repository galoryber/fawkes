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

        let pidMatch = combined.match(/Target PID:\s*(\d+)/i) || combined.match(/PID:\s*(\d+)/);
        let sizeMatch = combined.match(/[Ss]hellcode\s*(?:size)?:?\s*(\d+)\s*bytes/) || combined.match(/(\d+)\s*bytes/);
        let addrMatch = combined.match(/(?:at|address|allocated)\s*(0x[0-9A-Fa-f]+)/i);
        let syscallMatch = combined.match(/indirect syscalls/i);
        let success = combined.includes("successfully") || combined.includes("complete") || combined.includes("[+]");
        let failed = combined.includes("failed") || combined.includes("[!]") || combined.includes("Error");

        let headers = [
            {"plaintext": "Property", "type": "string", "width": 140},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let status = failed ? "FAILED" : (success ? "SUCCESS" : "UNKNOWN");
        let statusColor = failed ? "#f44336" : (success ? "#4CAF50" : "#FF9800");
        let statusBg = failed ? "rgba(244,67,54,0.1)" : (success ? "rgba(76,175,80,0.1)" : "rgba(255,152,0,0.1)");
        let rows = [
            {"Property": {"plaintext": "Technique"}, "Value": {"plaintext": "Threadless Injection", "cellStyle": {"fontWeight": "bold"}}, "rowStyle": {}},
            {"Property": {"plaintext": "Status"}, "Value": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": statusColor}}, "rowStyle": {"backgroundColor": statusBg}},
        ];
        if(pidMatch) rows.push({"Property": {"plaintext": "Target PID"}, "Value": {"plaintext": pidMatch[1], "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(sizeMatch) rows.push({"Property": {"plaintext": "Shellcode Size"}, "Value": {"plaintext": sizeMatch[1] + " bytes"}, "rowStyle": {}});
        if(addrMatch) rows.push({"Property": {"plaintext": "Remote Address"}, "Value": {"plaintext": addrMatch[1], "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(syscallMatch) rows.push({"Property": {"plaintext": "Syscalls"}, "Value": {"plaintext": "Indirect (Nt* stubs)", "cellStyle": {"color": "#4CAF50"}}, "rowStyle": {}});

        return {"table": [{"headers": headers, "rows": rows, "title": "Threadless technique injection"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
