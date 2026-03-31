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
        // Parse: [*] WinRM user@host:port (shell, auth)
        let headerMatch = combined.match(/\[\*\]\s+WinRM\s+(.+?)@(.+?):(\d+)\s+\((.+?),\s*(.+?)\)/);
        if(!headerMatch){
            return {"plaintext": combined};
        }
        let user = headerMatch[1];
        let host = headerMatch[2];
        let port = headerMatch[3];
        let shell = headerMatch[4];
        let auth = headerMatch[5];

        let cmdMatch = combined.match(/\[\*\]\s+Command:\s+(.+)/);
        let command = cmdMatch ? cmdMatch[1].trim() : "";

        let exitMatch = combined.match(/\[\*\]\s+Exit Code:\s+(\d+)/);
        let exitCode = exitMatch ? exitMatch[1] : "?";

        // Extract output after the dash separator
        let dashIdx = combined.indexOf("----");
        let output = "";
        let stderr = "";
        if(dashIdx >= 0){
            let afterDash = combined.substring(dashIdx);
            let newlineIdx = afterDash.indexOf("\n");
            if(newlineIdx >= 0){
                let rest = afterDash.substring(newlineIdx + 1);
                let stderrIdx = rest.indexOf("[STDERR]");
                if(stderrIdx >= 0){
                    output = rest.substring(0, stderrIdx).trim();
                    stderr = rest.substring(stderrIdx + 8).trim();
                } else {
                    output = rest.trim();
                }
            }
        }

        // Connection info table
        let connHeaders = [
            {"plaintext": "Property", "type": "string", "width": 120},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let exitStyle = {};
        if(exitCode === "0"){
            exitStyle = {"backgroundColor": "rgba(76,175,80,0.1)"};
        } else {
            exitStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
        }
        let connRows = [
            {"Property": {"plaintext": "Target"}, "Value": {"plaintext": user + "@" + host + ":" + port, "copyIcon": true}, "rowStyle": {}},
            {"Property": {"plaintext": "Shell"}, "Value": {"plaintext": shell}, "rowStyle": {}},
            {"Property": {"plaintext": "Auth"}, "Value": {"plaintext": auth}, "rowStyle": {}},
            {"Property": {"plaintext": "Command"}, "Value": {"plaintext": command, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}, "rowStyle": {}},
            {"Property": {"plaintext": "Exit Code"}, "Value": {"plaintext": exitCode}, "rowStyle": exitStyle},
        ];

        let tables = [{"headers": connHeaders, "rows": connRows, "title": "WinRM: " + host}];

        // Output table
        if(output){
            let outHeaders = [
                {"plaintext": "Output", "type": "string", "fillWidth": true},
            ];
            let outRows = [{
                "Output": {"plaintext": output, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em", "whiteSpace": "pre-wrap"}},
                "rowStyle": {},
            }];
            tables.push({"headers": outHeaders, "rows": outRows, "title": "stdout"});
        }
        if(stderr){
            let errHeaders = [
                {"plaintext": "Error Output", "type": "string", "fillWidth": true},
            ];
            let errRows = [{
                "Error Output": {"plaintext": stderr, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em", "whiteSpace": "pre-wrap", "color": "#d32f2f"}},
                "rowStyle": {"backgroundColor": "rgba(255,0,0,0.06)"},
            }];
            tables.push({"headers": errHeaders, "rows": errRows, "title": "stderr"});
        }
        return {"table": tables};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
