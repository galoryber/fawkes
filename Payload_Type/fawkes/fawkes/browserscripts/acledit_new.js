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
        if(data.mode === "acl-edit-read"){
            let riskColors = {
                "CRITICAL": "rgba(255,0,0,0.15)",
                "HIGH": "rgba(255,100,0,0.12)",
                "MEDIUM": "rgba(255,165,0,0.10)",
                "LOW": "rgba(100,149,237,0.08)",
            };
            let headers = [
                {"plaintext": "Principal", "type": "string", "fillWidth": true},
                {"plaintext": "SID", "type": "string", "width": 180},
                {"plaintext": "Type", "type": "string", "width": 170},
                {"plaintext": "Permissions", "type": "string", "width": 220},
                {"plaintext": "Risk", "type": "string", "width": 90},
            ];
            let rows = [];
            let aces = data.aces || [];
            for(let j = 0; j < aces.length; j++){
                let ace = aces[j];
                let risk = (ace.risk || "").toUpperCase();
                let rowStyle = {};
                if(riskColors[risk]){
                    rowStyle = {"backgroundColor": riskColors[risk]};
                }
                let riskStyle = {};
                if(risk === "CRITICAL" || risk === "HIGH"){
                    riskStyle = {"color": "#d32f2f", "fontWeight": "bold"};
                } else if(risk === "MEDIUM"){
                    riskStyle = {"color": "#ff8c00", "fontWeight": "bold"};
                }
                rows.push({
                    "Principal": {"plaintext": ace.principal || "", "copyIcon": true},
                    "SID": {"plaintext": ace.sid || "", "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}},
                    "Type": {"plaintext": ace.type || ""},
                    "Permissions": {"plaintext": ace.permissions || ""},
                    "Risk": {"plaintext": ace.risk || "", "cellStyle": riskStyle},
                    "rowStyle": rowStyle,
                });
            }
            let title = "ACL — " + (data.target || "?") + " (Owner: " + (data.owner || "?") + ", " + aces.length + " ACEs)";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        if(data.mode === "acl-edit-backup"){
            let headers = [
                {"plaintext": "Property", "type": "string", "width": 120},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = [
                {"Property": {"plaintext": "Target"}, "Value": {"plaintext": data.target || "", "copyIcon": true}},
                {"Property": {"plaintext": "Backup"}, "Value": {"plaintext": data.backup || "", "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}}},
            ];
            return {"table": [{"headers": headers, "rows": rows, "title": "ACL Backup"}]};
        }
        return {"plaintext": combined};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
