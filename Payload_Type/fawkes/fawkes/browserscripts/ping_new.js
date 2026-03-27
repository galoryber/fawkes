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
        let summary = "";
        let sweepInfo = "";
        let inTable = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            // Sweep header
            let sweepMatch = trimmed.match(/\[\*\] TCP ping sweep .+ (\d+ hosts).+port (\d+)/);
            if(sweepMatch){
                sweepInfo = sweepMatch[1] + ", port " + sweepMatch[2];
                continue;
            }
            if(trimmed.startsWith("HOST") && trimmed.includes("STATUS")){
                inTable = true;
                continue;
            }
            if(trimmed.match(/^-{10,}/)) continue;
            // Summary line
            let sumMatch = trimmed.match(/\[\*\] Results: (.+)/);
            if(sumMatch){
                summary = sumMatch[1];
                continue;
            }
            if(trimmed === "") continue;
            if(!inTable) continue;
            // Parse: "192.168.1.1      80       open         2.5ms"
            let match = trimmed.match(/^(\S+)\s+(\d+)\s+(\S+)\s+(.*)/);
            if(match){
                entries.push({
                    host: match[1],
                    port: parseInt(match[2]),
                    status: match[3],
                    latency: match[4].trim()
                });
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Host", "type": "string", "fillWidth": true},
            {"plaintext": "Port", "type": "number", "width": 80},
            {"plaintext": "Status", "type": "string", "width": 100},
            {"plaintext": "Latency", "type": "string", "width": 120}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let rowStyle = {};
            let statusStyle = {};
            if(e.status === "open"){
                statusStyle = {"color": "#4caf50", "fontWeight": "bold"};
            } else if(e.status === "closed" || e.status === "filtered"){
                statusStyle = {"color": "#ff4444"};
            }
            rows.push({
                "Host": {"plaintext": e.host, "copyIcon": true},
                "Port": {"plaintext": String(e.port)},
                "Status": {"plaintext": e.status, "cellStyle": statusStyle},
                "Latency": {"plaintext": e.latency},
                "rowStyle": rowStyle
            });
        }
        let title = "Ping Sweep";
        if(summary) title += " (" + summary + ")";
        else if(sweepInfo) title += " (" + sweepInfo + ", " + entries.length + " results)";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
