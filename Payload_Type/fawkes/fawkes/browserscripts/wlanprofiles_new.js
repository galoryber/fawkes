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
        // Try JSON
        try {
            let data = JSON.parse(combined);
            if(Array.isArray(data)){
                let headers = [
                    {"plaintext": "SSID", "type": "string", "width": 200},
                    {"plaintext": "Auth", "type": "string", "width": 120},
                    {"plaintext": "Password", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let i = 0; i < data.length; i++){
                    let e = data[i];
                    let rowStyle = {};
                    if(e.password || e.key){
                        rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
                    }
                    rows.push({
                        "SSID": {"plaintext": e.ssid || e.name || ""},
                        "Auth": {"plaintext": e.auth || e.authentication || ""},
                        "Password": {"plaintext": e.password || e.key || "(none)", "copyIcon": true},
                        "rowStyle": rowStyle
                    });
                }
                return {"table": [{"headers": headers, "rows": rows, "title": "WiFi Profiles (" + data.length + ")"}]};
            }
        } catch(e){}
        // Text fallback
        let lines = combined.split("\n").filter(l => l.trim());
        let rows = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let rowStyle = {};
            if(line.includes("Password:") || line.includes("Key:")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
            } else if(line.includes("SSID:") || line.includes("Profile:")){
                rowStyle = {"backgroundColor": "rgba(0,120,255,0.05)"};
            }
            rows.push({
                "Output": {"plaintext": line, "copyIcon": true},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{
            "headers": [{"plaintext": "Output", "type": "string", "fillWidth": true}],
            "rows": rows,
            "title": "WiFi Profiles"
        }]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
