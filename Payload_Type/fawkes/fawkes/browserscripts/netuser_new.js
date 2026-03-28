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
        // Check for simple action result (add, delete, password, group-add, group-remove)
        if(combined.startsWith("Successfully ")){
            return {"plaintext": combined};
        }
        let lines = combined.split("\n").filter(l => l.trim().length > 0);
        // Parse key-value pairs from info output
        let entries = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let match = line.match(/^(.+?):\s+(.*)/);
            if(match){
                entries.push({key: match[1].trim(), value: match[2].trim()});
            }
        }
        if(entries.length < 3){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Property", "type": "string", "width": 200},
            {"plaintext": "Value", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        let username = "";
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            if(e.key === "User") username = e.value;
            let valStyle = {};
            let rowStyle = {};
            // Highlight privilege level
            if(e.key === "Privilege" && e.value === "Administrator"){
                valStyle = {"color": "#d94f00", "fontWeight": "bold"};
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
            }
            // Highlight disabled/locked status
            if(e.key === "Flags"){
                if(e.value.includes("Disabled")){
                    valStyle = {"color": "#999"};
                } else if(e.value.includes("Locked")){
                    valStyle = {"color": "#d94f00", "fontWeight": "bold"};
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
                }
            }
            // Highlight "Password Never Expires"
            if(e.key === "Flags" && e.value.includes("Password Never Expires")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
            }
            rows.push({
                "Property": {"plaintext": e.key, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": e.value, "copyIcon": true, "cellStyle": valStyle},
                "rowStyle": rowStyle
            });
        }
        let title = username ? "User Info \u2014 " + username : "User Info";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
