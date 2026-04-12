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
            {"plaintext": "Property", "type": "string", "width": 150},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let lines = combined.split("\n");
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(!line) continue;
            let colonIdx = line.indexOf(":");
            if(colonIdx === -1) continue;
            let key = line.substring(0, colonIdx).trim();
            let value = line.substring(colonIdx + 1).trim();
            if(!key || !value) continue;
            let cellStyle = {};
            let rowStyle = {};
            if(key === "User" || key === "Host"){
                cellStyle = {"fontWeight": "bold", "color": "#2196f3"};
            } else if(key === "Privilege" || key === "Integrity"){
                let lv = value.toLowerCase();
                if(lv.includes("system") || lv.includes("root") || lv === "4"){
                    cellStyle = {"fontWeight": "bold", "color": "#e74c3c"};
                } else if(lv.includes("admin") || lv.includes("high") || lv === "3"){
                    cellStyle = {"fontWeight": "bold", "color": "#e67e22"};
                }
            } else if(key === "UID" || key === "GID" || key === "EUID" || key === "PID"){
                cellStyle = {"fontFamily": "monospace"};
            } else if(key === "Container"){
                rowStyle = {"backgroundColor": "rgba(156,39,176,0.08)"};
                cellStyle = {"fontWeight": "bold"};
            } else if(key === "Groups" || key === "Capabilities"){
                cellStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
            }
            rows.push({
                "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": value, "copyIcon": true, "cellStyle": cellStyle},
                "rowStyle": rowStyle,
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Identity Information"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
