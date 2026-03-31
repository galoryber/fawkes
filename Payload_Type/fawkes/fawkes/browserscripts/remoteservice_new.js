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
        // "list" action: parse service table
        if(combined.includes("Services on") && combined.includes("total)")){
            let lines = combined.split("\n");
            let services = [];
            let pastHeader = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.match(/^-{10,}$/)){
                    pastHeader = true;
                    continue;
                }
                if(!pastHeader || trimmed.length === 0) continue;
                if(trimmed.startsWith("SERVICE NAME")) continue;
                let parts = trimmed.split(/\s{2,}/);
                if(parts.length >= 2){
                    let name = parts[0].trim();
                    let state = parts[1].trim();
                    let display = parts.length >= 3 ? parts.slice(2).join(" ").trim() : "";
                    services.push({name: name, state: state, display: display});
                }
            }
            if(services.length > 0){
                let headers = [
                    {"plaintext": "Service Name", "type": "string", "fillWidth": true},
                    {"plaintext": "State", "type": "string", "width": 90},
                    {"plaintext": "Display Name", "type": "string", "width": 300},
                ];
                let rows = [];
                for(let j = 0; j < services.length; j++){
                    let s = services[j];
                    let isRunning = s.state.toLowerCase() === "running";
                    let isStopped = s.state.toLowerCase() === "stopped";
                    let stateStyle = {};
                    if(isRunning) stateStyle = {"color": "#4caf50", "fontWeight": "bold"};
                    else if(isStopped) stateStyle = {"color": "#888"};
                    rows.push({
                        "Service Name": {"plaintext": s.name, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                        "State": {"plaintext": s.state, "cellStyle": stateStyle},
                        "Display Name": {"plaintext": s.display},
                        "rowStyle": isRunning ? {"backgroundColor": "rgba(76,175,80,0.06)"} : {},
                    });
                }
                let hostMatch = combined.match(/Services on\s+(\S+)/);
                let host = hostMatch ? hostMatch[1] : "?";
                return {"table": [{"headers": headers, "rows": rows, "title": "Services on " + host + " — " + services.length + " total"}]};
            }
        }
        // "query" action: parse key-value service details
        if(combined.includes("Service:") && combined.includes("Binary Path")){
            let lines = combined.split("\n");
            let headers = [
                {"plaintext": "Property", "type": "string", "width": 150},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.length === 0) continue;
                let kvMatch = trimmed.match(/^(.+?)\s*:\s+(.*)/);
                if(kvMatch){
                    let key = kvMatch[1].trim();
                    let val = kvMatch[2].trim();
                    let valStyle = {};
                    if(key === "State"){
                        if(val.toLowerCase() === "running") valStyle = {"color": "#4caf50", "fontWeight": "bold"};
                        else if(val.toLowerCase() === "stopped") valStyle = {"color": "#888"};
                    }
                    if(key === "Binary Path") valStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
                    rows.push({
                        "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                        "Value": {"plaintext": val, "cellStyle": valStyle, "copyIcon": true},
                        "rowStyle": {},
                    });
                }
            }
            if(rows.length > 0){
                let svcMatch = combined.match(/Service:\s+(.*)/);
                let title = svcMatch ? "Service: " + svcMatch[1].trim() : "Service Details";
                return {"table": [{"headers": headers, "rows": rows, "title": title}]};
            }
        }
        return {"plaintext": combined};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
