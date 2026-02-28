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
        let data = JSON.parse(combined);
        // getprivs list returns an object with identity, integrity, privileges array
        if(!data.privileges || !Array.isArray(data.privileges)){
            return {"plaintext": combined};
        }
        let statusColors = {
            "Enabled": "rgba(0,200,0,0.15)",
            "Enabled (Default)": "rgba(0,200,0,0.1)",
            "Disabled": "rgba(255,255,255,0)",
        };
        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "status", "type": "string", "width": 140},
            {"plaintext": "description", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let enabledCount = 0;
        for(let j = 0; j < data.privileges.length; j++){
            let p = data.privileges[j];
            if(p.status === "Enabled" || p.status === "Enabled (Default)"){
                enabledCount++;
            }
            let rowStyle = {};
            if(statusColors[p.status] !== undefined){
                rowStyle = {"backgroundColor": statusColors[p.status]};
            }
            rows.push({
                "name": {"plaintext": p.name, "copyIcon": true},
                "status": {"plaintext": p.status},
                "description": {"plaintext": p.description || ""},
                "rowStyle": rowStyle,
            });
        }
        let tables = [{
            "headers": headers,
            "rows": rows,
            "title": "Token Privileges — " + enabledCount + "/" + data.privileges.length + " enabled",
        }];
        // Add identity info table
        let infoHeaders = [
            {"plaintext": "field", "type": "string", "width": 120},
            {"plaintext": "value", "type": "string", "fillWidth": true},
        ];
        let infoRows = [];
        if(data.identity) infoRows.push({"field": {"plaintext": "Identity"}, "value": {"plaintext": data.identity, "copyIcon": true}});
        if(data.source) infoRows.push({"field": {"plaintext": "Source"}, "value": {"plaintext": data.source}});
        if(data.integrity) infoRows.push({"field": {"plaintext": "Integrity"}, "value": {"plaintext": data.integrity}});
        if(infoRows.length > 0){
            tables.unshift({"headers": infoHeaders, "rows": infoRows, "title": "Token Info"});
        }
        return {"table": tables};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
