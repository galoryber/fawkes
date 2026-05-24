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
            {"plaintext": "Property", "type": "string", "width": 160},
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
                    "Property": {"plaintext": line, "cellStyle": {"fontWeight": "bold", "backgroundColor": "rgba(33,150,243,0.08)"}},
                    "Value": {"plaintext": ""},
                    "rowStyle": {"backgroundColor": "rgba(33,150,243,0.05)"},
                });
                continue;
            }
            let key = line.substring(0, colonIdx).trim();
            let value = line.substring(colonIdx + 1).trim();
            if(!key) continue;
            let cellStyle = {};
            if(key === "PID" || key === "PPID" || key.includes("address") || key.includes("port")){
                cellStyle = {"fontFamily": "monospace"};
            } else if(key === "Status" || key === "State"){
                let lv = value.toLowerCase();
                cellStyle = {"fontWeight": "bold", "color": lv.includes("running") || lv.includes("sleeping") ? "#2ecc71" : "#e67e22"};
            } else if(key === "Capabilities" || key === "Namespaces"){
                cellStyle = {"fontFamily": "monospace", "fontSize": "0.85em"};
            }
            rows.push({
                "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": value, "copyIcon": true, "cellStyle": cellStyle},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        let title = "Process Information";
        if(task.original_params){
            try {
                let params = JSON.parse(task.original_params);
                if(params.pid) title += " \u2014 PID " + params.pid;
            } catch(e){}
        }
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
