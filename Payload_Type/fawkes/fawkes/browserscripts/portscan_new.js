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
    if(combined.includes("=== Network Recon Chain") || combined.includes("[Step ")){
        return renderChainTable(combined, "Network Recon Chain");
    }
    try {
        let lines = combined.split("\n");
        let summaryLine = "";
        let results = [];
        let inTable = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(line.startsWith("Scanned ")){
                summaryLine = line;
            } else if(line.match(/^-{10,}$/)){
                inTable = true;
                continue;
            } else if(inTable && line.length > 0){
                let parts = line.split(/\s+/);
                if(parts.length >= 2){
                    let host = parts[0];
                    let port = parts[1];
                    let service = parts.length >= 3 ? parts.slice(2).join(" ") : "";
                    results.push({host: host, port: parseInt(port) || port, service: service});
                }
            }
        }
        if(results.length === 0){
            return {"plaintext": combined};
        }
        let criticalPorts = new Set([21, 23, 445, 3389, 5985, 5986, 1433, 3306, 5432]);
        let webPorts = new Set([80, 443, 8080, 8443]);
        let headers = [
            {"plaintext": "Host", "type": "string", "width": 180},
            {"plaintext": "Port", "type": "number", "width": 80},
            {"plaintext": "Service", "type": "string", "width": 120},
            {"plaintext": "actions", "type": "button", "width": 90, "disableSort": true},
        ];
        let rows = [];
        for(let j = 0; j < results.length; j++){
            let r = results[j];
            let portNum = typeof r.port === "number" ? r.port : parseInt(r.port);
            let rowStyle = {};
            if(criticalPorts.has(portNum)){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            } else if(webPorts.has(portNum)){
                rowStyle = {"backgroundColor": "rgba(0,150,255,0.1)"};
            }
            let localPort = portNum < 1024 ? portNum + 10000 : portNum + 1000;
            if(localPort > 65535){ localPort = 7000; }
            rows.push({
                "Host": {"plaintext": r.host, "copyIcon": true},
                "Port": {"plaintext": String(r.port)},
                "Service": {"plaintext": r.service || "—"},
                "rowStyle": rowStyle,
                "actions": {
                    "button": {
                        "name": "rpfwd",
                        "type": "task",
                        "ui_feature": "port_browser:forward",
                        "startIcon": "link",
                        "hoverText": "Forward port " + r.port + " from " + r.host + " via agent",
                        "parameters": "forward " + localPort + " " + r.host + " " + String(r.port),
                    }
                },
            });
        }
        let title = "Port Scan — " + results.length + " open ports";
        if(summaryLine) title += " (" + summaryLine + ")";
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    } catch(error) {
        return {"plaintext": combined};
    }
}

function renderChainTable(text, chainName){
    let lines = text.split("\n");
    let headers = [
        {"plaintext": "Status", "type": "string", "width": 100},
        {"plaintext": "Command", "type": "string", "width": 200},
        {"plaintext": "Detail", "type": "string", "fillWidth": true},
    ];
    let rows = [];
    let successCount = 0;
    let errorCount = 0;
    for(let i = 0; i < lines.length; i++){
        let line = lines[i].trim();
        if(!line || line.match(/^={3,}$/)) continue;
        let stepMatch = line.match(/^\[Step (\d+\/\d+)\]\s+(.*)/);
        if(stepMatch){
            rows.push({
                "Status": {"plaintext": stepMatch[1], "cellStyle": {"fontWeight": "bold", "color": "#2196f3"}},
                "Command": {"plaintext": "Progress"},
                "Detail": {"plaintext": stepMatch[2]},
                "rowStyle": {"backgroundColor": "rgba(33,150,243,0.08)"},
            });
            continue;
        }
        let taskMatch = line.match(/^\[(success|error|unknown)\]\s+(\S+)\s+(.*)/);
        if(taskMatch){
            let status = taskMatch[1].toUpperCase();
            let isSuccess = status === "SUCCESS";
            if(isSuccess) successCount++;
            else if(status === "ERROR") errorCount++;
            rows.push({
                "Status": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": isSuccess ? "#4caf50" : (status === "ERROR" ? "#f44336" : "#9e9e9e")}},
                "Command": {"plaintext": taskMatch[2]},
                "Detail": {"plaintext": taskMatch[3]},
                "rowStyle": {"backgroundColor": isSuccess ? "rgba(76,175,80,0.08)" : (status === "ERROR" ? "rgba(244,67,54,0.08)" : "")},
            });
            continue;
        }
        if(line.startsWith("Total:") || line.startsWith("=== ")) continue;
    }
    let title = chainName;
    if(successCount + errorCount > 0){
        title += " — " + successCount + " success";
        if(errorCount > 0) title += ", " + errorCount + " errors";
    }
    return {"table": [{"headers": headers, "rows": rows, "title": title}]};
}
