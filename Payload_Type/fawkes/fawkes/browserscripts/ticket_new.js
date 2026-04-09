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
        let lines = combined.split("\n").filter(l => l.trim());
        let entries = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            // Parse "Key: Value" lines
            let match = line.match(/^([A-Za-z][A-Za-z\s\/()-]+?):\s+(.+)/);
            if(match){
                entries.push({key: match[1].trim(), value: match[2].trim()});
            }
        }
        if(entries.length >= 2){
            let headers = [
                {"plaintext": "Property", "type": "string", "width": 200},
                {"plaintext": "Value", "type": "string", "fillWidth": true}
            ];
            let rows = [];
            for(let i = 0; i < entries.length; i++){
                let rowStyle = {};
                let e = entries[i];
                if(e.key === "Key (base64)" || e.key === "Recovery Key (base64)"){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                } else if(e.key === "Algorithm" || e.key === "Format"){
                    rowStyle = {"backgroundColor": "rgba(0,120,255,0.05)"};
                } else if(e.value.includes("Administrator") || e.value.includes("SYSTEM")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
                }
                rows.push({
                    "Property": {"plaintext": e.key},
                    "Value": {"plaintext": e.value, "copyIcon": true},
                    "rowStyle": rowStyle
                });
            }
            let title = "Kerberos Ticket";
            for(let i = 0; i < entries.length; i++){
                if(entries[i].key === "Action"){
                    title = "Kerberos " + entries[i].value;
                    break;
                }
            }
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        return {"plaintext": combined};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
