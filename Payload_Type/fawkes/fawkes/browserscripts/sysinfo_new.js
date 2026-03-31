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

        // Parse key: value lines
        let lines = combined.split("\n");
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(!line) continue;
            let colonIdx = line.indexOf(":");
            if(colonIdx === -1) continue;
            let key = line.substring(0, colonIdx).trim();
            let value = line.substring(colonIdx + 1).trim();
            if(!key || !value) continue;

            let rowStyle = {};
            let cellStyle = {};
            // Highlight security-relevant fields
            if(key === "Hostname" || key === "Domain" || key === "User"){
                cellStyle = {"fontWeight": "bold"};
            } else if(key === "PID" || key === "PPID"){
                cellStyle = {"fontFamily": "monospace"};
            } else if(key.includes("IP") || key.includes("MAC") || key.includes("Interface")){
                cellStyle = {"fontFamily": "monospace"};
                rowStyle = {"backgroundColor": "rgba(33,150,243,0.05)"};
            }

            rows.push({
                "Property": {"plaintext": key},
                "Value": {"plaintext": value, "copyIcon": true, "cellStyle": cellStyle},
                "rowStyle": rowStyle,
            });
        }

        if(rows.length === 0){
            return {"plaintext": combined};
        }

        return {"table": [{"headers": headers, "rows": rows, "title": "System Information"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
