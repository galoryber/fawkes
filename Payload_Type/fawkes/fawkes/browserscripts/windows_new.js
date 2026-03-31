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
        let lines = combined.split("\n");
        let windows = [];
        let summaryLine = "";
        let pastHeader = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed.startsWith("[*]") || trimmed.startsWith("[+]")){
                summaryLine = trimmed;
                continue;
            }
            if(trimmed.match(/^-{10,}$/)){
                pastHeader = true;
                continue;
            }
            if(trimmed.startsWith("HWND")){
                pastHeader = true;
                continue;
            }
            if(!pastHeader) continue;
            if(trimmed.length === 0) continue;
            // Parse the fixed-width format: HWND(8) PID(6) Process(25) Class(30) Title(rest)
            let match = trimmed.match(/^(0x[0-9A-Fa-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)/);
            if(match){
                let hidden = match[5].includes("[hidden]");
                let title = match[5].replace(" [hidden]", "").trim();
                windows.push({
                    hwnd: match[1],
                    pid: parseInt(match[2]),
                    process: match[3],
                    className: match[4],
                    title: title,
                    visible: !hidden,
                });
            }
        }
        if(windows.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "PID", "type": "number", "width": 70},
            {"plaintext": "Process", "type": "string", "width": 180},
            {"plaintext": "Title", "type": "string", "fillWidth": true},
            {"plaintext": "Class", "type": "string", "width": 200},
            {"plaintext": "Visible", "type": "string", "width": 70},
        ];
        let rows = [];
        // Sensitive process names to highlight
        let securityProcs = ["msedge", "chrome", "firefox", "outlook", "teams", "slack", "keepass", "1password", "bitwarden", "putty", "winscp", "rdpclip", "mstsc"];
        for(let j = 0; j < windows.length; j++){
            let w = windows[j];
            let procStyle = {};
            let titleStyle = {};
            let lowerProc = (w.process || "").toLowerCase();
            // Highlight security-relevant processes
            for(let s = 0; s < securityProcs.length; s++){
                if(lowerProc.includes(securityProcs[s])){
                    procStyle = {"color": "#e67e22", "fontWeight": "bold"};
                    break;
                }
            }
            if(!w.visible){
                titleStyle = {"color": "#999", "fontStyle": "italic"};
            }
            rows.push({
                "PID": {"plaintext": String(w.pid)},
                "Process": {"plaintext": w.process || "", "cellStyle": procStyle},
                "Title": {"plaintext": w.title || "", "copyIcon": w.title.length > 0, "cellStyle": titleStyle},
                "Class": {"plaintext": w.className || "", "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Visible": {"plaintext": w.visible ? "\u2714" : "\u2716", "cellStyle": {"textAlign": "center", "color": w.visible ? "#2ecc71" : "#e74c3c"}},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": summaryLine || ("Application Windows \u2014 " + windows.length + " found"),
            }]
        };
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
