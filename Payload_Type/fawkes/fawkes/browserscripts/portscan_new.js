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
        // Parse header lines for summary
        let summaryLine = "";
        let foundLine = "";
        let results = [];
        let inTable = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(line.startsWith("Scanned ")){
                summaryLine = line;
            } else if(line.startsWith("Found ")){
                foundLine = line;
            } else if(line.match(/^-{10,}$/)){
                inTable = true;
                continue;
            } else if(inTable && line.length > 0){
                // Parse: Host                 Port     Service
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
        // Color-code by service type
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
            // Local listen port: offset to avoid well-known port restrictions
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
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
