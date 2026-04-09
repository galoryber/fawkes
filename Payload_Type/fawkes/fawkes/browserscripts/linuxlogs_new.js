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
        // Try JSON first
        try {
            let data = JSON.parse(combined);
            if(Array.isArray(data)){
                let headers = [
                    {"plaintext": "User", "type": "string", "width": 120},
                    {"plaintext": "Terminal", "type": "string", "width": 100},
                    {"plaintext": "Host", "type": "string", "width": 150},
                    {"plaintext": "Time", "type": "string", "width": 180},
                    {"plaintext": "Type", "type": "string", "width": 100}
                ];
                let rows = [];
                for(let i = 0; i < data.length; i++){
                    let e = data[i];
                    let rowStyle = {};
                    if(e.type === "LOGIN" || e.type === "USER_PROCESS"){
                        rowStyle = {"backgroundColor": "rgba(0,255,0,0.05)"};
                    } else if(e.type === "BOOT_TIME"){
                        rowStyle = {"backgroundColor": "rgba(0,120,255,0.05)"};
                    }
                    rows.push({
                        "User": {"plaintext": e.user || ""},
                        "Terminal": {"plaintext": e.terminal || e.line || ""},
                        "Host": {"plaintext": e.host || ""},
                        "Time": {"plaintext": e.time || ""},
                        "Type": {"plaintext": e.type || ""},
                        "rowStyle": rowStyle
                    });
                }
                return {"table": [{"headers": headers, "rows": rows, "title": "Log Entries (" + data.length + ")"}]};
            }
        } catch(e){}
        // Fallback to text line display
        let lines = combined.split("\n").filter(l => l.trim());
        let rows = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let rowStyle = {};
            if(line.includes("root") || line.includes("sudo")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
            } else if(line.includes("fail") || line.includes("error") || line.includes("denied")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
            }
            rows.push({
                "Entry": {"plaintext": line},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{
            "headers": [{"plaintext": "Entry", "type": "string", "fillWidth": true}],
            "rows": rows,
            "title": "Linux Logs (" + lines.length + " lines)"
        }]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
