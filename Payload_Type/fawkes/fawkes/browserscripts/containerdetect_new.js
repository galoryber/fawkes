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
        let entries = [];
        let environment = "";
        let inTable = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            let envMatch = trimmed.match(/Environment:\s+(.+)/);
            if(envMatch){
                environment = envMatch[1];
                continue;
            }
            if(trimmed.startsWith("Check") && trimmed.includes("Result")){
                inTable = true;
                continue;
            }
            if(trimmed.match(/^-{10,}/)) continue;
            if(trimmed === "" || trimmed.startsWith("[*]")) continue;
            if(!inTable) continue;
            let match = line.match(/^(.{35})\s*(\S+)\s+(.*)/);
            if(match){
                entries.push({
                    check: match[1].trim(),
                    result: match[2].trim(),
                    details: match[3].trim()
                });
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Result", "type": "string", "width": 110},
            {"plaintext": "Check", "type": "string", "width": 250},
            {"plaintext": "Details", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        let escapeCount = 0;
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let rowStyle = {};
            let resultStyle = {};
            let r = e.result.toUpperCase();
            if(r === "ESCAPE"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
                resultStyle = {"color": "#ff4444", "fontWeight": "bold"};
                escapeCount++;
            } else if(r === "FOUND" || r === "DOCKER" || r === "CONTAINER" || r === "K8S" || r === "LXC"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                resultStyle = {"color": "#ff8c00", "fontWeight": "bold"};
            } else if(r === "ABSENT" || r === "CLEAN"){
                resultStyle = {"color": "#4caf50"};
            } else if(r === "INFO" || r === "REDUCED"){
                resultStyle = {"color": "#0096ff"};
            }
            rows.push({
                "Result": {"plaintext": e.result, "cellStyle": resultStyle},
                "Check": {"plaintext": e.check},
                "Details": {"plaintext": e.details, "copyIcon": true},
                "rowStyle": rowStyle
            });
        }
        let title = "Container Detection (" + entries.length + " checks";
        if(environment) title += ", Environment: " + environment;
        if(escapeCount > 0) title += ", " + escapeCount + " escape vectors";
        title += ")";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
