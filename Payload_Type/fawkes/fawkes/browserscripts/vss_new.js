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
        // Try JSON for structured VSS data
        try {
            let data = JSON.parse(combined);
            if(Array.isArray(data)){
                let headers = [
                    {"plaintext": "ID", "type": "string", "width": 80},
                    {"plaintext": "Volume", "type": "string", "width": 100},
                    {"plaintext": "Created", "type": "string", "width": 180},
                    {"plaintext": "Path", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let i = 0; i < data.length; i++){
                    let e = data[i];
                    rows.push({
                        "ID": {"plaintext": String(e.id || i+1)},
                        "Volume": {"plaintext": e.volume || ""},
                        "Created": {"plaintext": e.created || e.timestamp || ""},
                        "Path": {"plaintext": e.path || e.device_object || "", "copyIcon": true}
                    });
                }
                return {"table": [{"headers": headers, "rows": rows, "title": "Volume Shadow Copies (" + data.length + ")"}]};
            }
        } catch(e){}
        // Text line display with coloring
        let lines = combined.split("\n").filter(l => l.trim());
        let rows = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            let rowStyle = {};
            if(line.includes("[+]") || line.includes("Created") || line.includes("listed")){
                rowStyle = {"backgroundColor": "rgba(0,255,0,0.05)"};
            } else if(line.includes("deleted") || line.includes("Deleted")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
            }
            rows.push({
                "Output": {"plaintext": line},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{
            "headers": [{"plaintext": "Output", "type": "string", "fillWidth": true}],
            "rows": rows,
            "title": "Volume Shadow Copies"
        }]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
