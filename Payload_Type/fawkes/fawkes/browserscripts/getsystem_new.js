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
            {"plaintext": "Property", "type": "string", "width": 130},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let lines = combined.split("\n");
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(!line) continue;
            let colonIdx = line.indexOf(":");
            if(colonIdx === -1){
                let isSuccess = line.toLowerCase().includes("success") || line.toLowerCase().includes("elevated");
                rows.push({
                    "Property": {"plaintext": "Status", "cellStyle": {"fontWeight": "bold"}},
                    "Value": {"plaintext": line, "cellStyle": {"fontWeight": "bold", "color": isSuccess ? "#2ecc71" : "#e74c3c"}},
                });
                continue;
            }
            let key = line.substring(0, colonIdx).trim();
            let value = line.substring(colonIdx + 1).trim();
            if(!key) continue;
            let cellStyle = {};
            if(key === "Old" || key === "Previous"){
                cellStyle = {"color": "#95a5a6"};
            } else if(key === "New" || key === "Current"){
                cellStyle = {"fontWeight": "bold", "color": "#e74c3c"};
            } else if(key === "Technique"){
                cellStyle = {"fontFamily": "monospace"};
            }
            rows.push({
                "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": value, "copyIcon": true, "cellStyle": cellStyle},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Privilege Escalation"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
