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
            {"plaintext": "Property", "type": "string", "width": 200},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let lines = combined.split("\n");
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(!line) continue;
            let colonIdx = line.indexOf(":");
            if(colonIdx === -1){
                rows.push({
                    "Property": {"plaintext": line, "cellStyle": {"fontWeight": "bold"}},
                    "Value": {"plaintext": ""},
                });
                continue;
            }
            let key = line.substring(0, colonIdx).trim();
            let value = line.substring(colonIdx + 1).trim();
            let cellStyle = {};
            if(key === "Status"){
                let isEnabled = value.toUpperCase().includes("ENABLED");
                cellStyle = {"fontWeight": "bold", "color": isEnabled ? "#e74c3c" : "#2ecc71"};
            } else if(key === "UseLogonCredential" || key === "Negotiate"){
                cellStyle = {"fontFamily": "monospace"};
            }
            rows.push({
                "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": value, "cellStyle": cellStyle},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "WDigest Credential Caching"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
