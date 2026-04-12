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
        let headers = [
            {"plaintext": "Step", "type": "string", "width": 60},
            {"plaintext": "Action", "type": "string", "width": 200},
            {"plaintext": "Status", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let host = "";
        let lines = combined.split("\n");
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(!line) continue;
            let hostMatch = line.match(/PSExec on (.+?):/);
            if(hostMatch){ host = hostMatch[1]; continue; }
            let stepMatch = line.match(/^\[(\d+)\]\s+(.+?)\.{3}\s*(.*)/);
            if(stepMatch){
                let status = stepMatch[3] || "...";
                let isOk = status.toLowerCase().includes("connected") || status.toLowerCase().includes("created") || status.toLowerCase().includes("started") || status.toLowerCase().includes("deleted") || status.toLowerCase().includes("success");
                let isFail = status.toLowerCase().includes("fail") || status.toLowerCase().includes("error");
                rows.push({
                    "Step": {"plaintext": stepMatch[1], "cellStyle": {"fontWeight": "bold", "textAlign": "center"}},
                    "Action": {"plaintext": stepMatch[2].trim()},
                    "Status": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": isFail ? "#e74c3c" : isOk ? "#2ecc71" : "#f39c12"}},
                });
                continue;
            }
            // fallback: non-step lines
            rows.push({
                "Step": {"plaintext": ""},
                "Action": {"plaintext": line},
                "Status": {"plaintext": ""},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        let title = "PSExec";
        if(host) title += " \u2014 " + host;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
