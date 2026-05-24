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
            {"plaintext": "", "type": "string", "width": 30},
            {"plaintext": "Step", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let lines = combined.split("\n");
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(!line) continue;
            let icon = "";
            let cellStyle = {};
            if(line.startsWith("[+]")){
                icon = "\u2705";
                line = line.substring(3).trim();
                cellStyle = {"color": "#2ecc71"};
            } else if(line.startsWith("[*]")){
                icon = "\u2139\ufe0f";
                line = line.substring(3).trim();
                cellStyle = {"fontWeight": "bold"};
            } else if(line.startsWith("[!]")){
                icon = "\u26a0\ufe0f";
                line = line.substring(3).trim();
                cellStyle = {"color": "#e74c3c", "fontWeight": "bold"};
            } else if(line.startsWith("[-]")){
                icon = "\u274c";
                line = line.substring(3).trim();
                cellStyle = {"color": "#e74c3c"};
            }
            rows.push({
                "": {"plaintext": icon},
                "Step": {"plaintext": line, "cellStyle": cellStyle},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Reflective PE Loader"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
