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
        let data;
        try { data = JSON.parse(combined); } catch(e) { return {"plaintext": combined}; }
        if(!Array.isArray(data)){
            return {"plaintext": combined};
        }
        if(data.length === 0){
            return {"plaintext": "No active background jobs"};
        }
        let headers = [
            {"plaintext": "ID", "type": "number", "width": 60},
            {"plaintext": "Command", "type": "string", "width": 200},
            {"plaintext": "Status", "type": "string", "width": 100},
            {"plaintext": "Started", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let j = data[i];
            let statusColor = j.status === "running" ? "#2ecc71" : (j.status === "completed" ? "#3498db" : "#e74c3c");
            rows.push({
                "ID": {"plaintext": String(j.id || i), "cellStyle": {"fontWeight": "bold"}},
                "Command": {"plaintext": j.command || j.name || "", "cellStyle": {"fontFamily": "monospace"}},
                "Status": {"plaintext": j.status || "unknown", "cellStyle": {"color": statusColor, "fontWeight": "bold"}},
                "Started": {"plaintext": j.started || j.start_time || ""},
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Background Jobs \u2014 " + data.length + " active"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
