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
        let lines = combined.split("\n");
        let entries = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.startsWith("[*]")) continue;
            let match = trimmed.match(/^(.+?):\s+(.*)/);
            if(match){
                entries.push({key: match[1].trim(), value: match[2].trim()});
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Property", "type": "string", "width": 160},
            {"plaintext": "Value", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let valStyle = {};
            if(e.key === "Uptime") valStyle = {"fontWeight": "bold"};
            if(e.key === "Load avg") valStyle = {"fontFamily": "monospace"};
            rows.push({
                "Property": {"plaintext": e.key, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": e.value, "cellStyle": valStyle, "copyIcon": true}
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "System Uptime"}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
