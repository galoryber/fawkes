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
        // Try JSON parse for structured thread/session data
        try {
            let data = JSON.parse(combined);
            if(Array.isArray(data)){
                let headers = [
                    {"plaintext": "Session", "type": "string", "width": 80},
                    {"plaintext": "User", "type": "string", "width": 150},
                    {"plaintext": "State", "type": "string", "width": 100},
                    {"plaintext": "ID", "type": "string", "width": 80},
                    {"plaintext": "Details", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let i = 0; i < data.length; i++){
                    let e = data[i];
                    let rowStyle = {};
                    if(e.state === "Active" || e.state === "active"){
                        rowStyle = {"backgroundColor": "rgba(0,255,0,0.05)"};
                    } else if(e.state === "Disconnected" || e.state === "disconnected"){
                        rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                    }
                    rows.push({
                        "Session": {"plaintext": String(e.session || e.id || i)},
                        "User": {"plaintext": e.user || e.username || ""},
                        "State": {"plaintext": e.state || ""},
                        "ID": {"plaintext": String(e.session_id || e.id || "")},
                        "Details": {"plaintext": e.details || e.client || e.info || ""},
                        "rowStyle": rowStyle
                    });
                }
                return {"table": [{"headers": headers, "rows": rows, "title": "Terminal Sessions (" + data.length + ")"}]};
            }
        } catch(e){}
        // Text fallback — parse line by line
        let lines = combined.split("\n").filter(l => l.trim());
        let rows = [];
        for(let i = 0; i < lines.length; i++){
            let rowStyle = {};
            if(lines[i].includes("Active") || lines[i].includes("SYSTEM")){
                rowStyle = {"backgroundColor": "rgba(0,120,255,0.05)"};
            }
            rows.push({
                "Output": {"plaintext": lines[i]},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{
            "headers": [{"plaintext": "Output", "type": "string", "fillWidth": true}],
            "rows": rows,
            "title": "Terminal Sessions"
        }]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
