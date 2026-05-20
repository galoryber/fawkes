function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = "";
    for(let i = 0; i < responses.length; i++){
        combined += responses[i];
    }

    let action = "list";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.action) action = params.action.toLowerCase();
        } catch(e){}
    }

    if(action === "list" && combined.includes("=== RDP SESSIONS ===")){
        try {
            let lines = combined.split("\n").filter(l => l.trim().length > 0);
            let currentSession = "";
            let sessionLines = [];
            for(let i = 0; i < lines.length; i++){
                let line = lines[i];
                if(line.startsWith("Current session:")){
                    currentSession = line.replace("Current session:", "").trim();
                    continue;
                }
                if(line.startsWith("===") || line.startsWith("ID ") || line.startsWith("---")){
                    continue;
                }
                let parts = line.trim().split(/\s{2,}/);
                if(parts.length >= 3){
                    sessionLines.push({
                        id: parts[0] || "",
                        station: parts[1] || "",
                        state: parts[2] || "",
                        username: parts[3] || "",
                        domain: parts[4] || "",
                    });
                }
            }
            if(sessionLines.length > 0){
                let headers = [
                    {"plaintext": "ID", "type": "number", "width": 60},
                    {"plaintext": "Station", "type": "string", "width": 160},
                    {"plaintext": "State", "type": "string", "width": 120},
                    {"plaintext": "Username", "type": "string", "width": 160},
                    {"plaintext": "Domain", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                for(let i = 0; i < sessionLines.length; i++){
                    let s = sessionLines[i];
                    let isCurrent = s.id === currentSession;
                    let stateColor = s.state === "Active" ? "#2ecc71" :
                                     s.state === "Connected" ? "#3498db" :
                                     s.state === "Disconnected" ? "#e74c3c" :
                                     s.state === "Idle" ? "#f39c12" : "#95a5a6";
                    let idStyle = isCurrent ? {"fontWeight": "bold", "color": "#2ecc71"} : {"fontWeight": "bold"};
                    rows.push({
                        "ID": {"plaintext": s.id + (isCurrent ? " *" : ""), "cellStyle": idStyle},
                        "Station": {"plaintext": s.station, "cellStyle": {"fontFamily": "monospace"}},
                        "State": {"plaintext": s.state, "cellStyle": {"color": stateColor, "fontWeight": "bold"}},
                        "Username": {"plaintext": s.username},
                        "Domain": {"plaintext": s.domain},
                    });
                }
                let title = "RDP Sessions — " + sessionLines.length + " sessions";
                if(currentSession) title += " (current: " + currentSession + ")";
                return {"table": [{"headers": headers, "rows": rows, "title": title}]};
            }
        } catch(e){}
    }

    let lines = combined.split("\n").filter(l => l.length > 0);
    let title = "tscon";
    if(action !== "list") title += " — " + action;
    title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
