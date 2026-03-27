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
        let drivers = [];
        let summaryLine = "";
        let pastHeader = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed.startsWith("Loaded Drivers") || trimmed.startsWith("Loaded Modules")){
                summaryLine = trimmed;
                continue;
            }
            // Skip separator and header lines
            if(trimmed.match(/^-{10,}$/)){
                pastHeader = true;
                continue;
            }
            if(!pastHeader) continue;
            if(trimmed.length === 0) continue;
            // Parse fixed-width columns: Name(30) Size(12) Path(55) Status(rest)
            // Or use whitespace splitting since values shouldn't have spaces except Path
            let parts = trimmed.split(/\s{2,}/);
            if(parts.length >= 2){
                let name = parts[0].trim();
                let size = parts.length >= 2 ? parts[1].trim() : "";
                let path = parts.length >= 3 ? parts[2].trim() : "";
                let status = parts.length >= 4 ? parts[3].trim() : "";
                drivers.push({name: name, size: size, path: path, status: status});
            }
        }
        if(drivers.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Name", "type": "string", "width": 200},
            {"plaintext": "Size", "type": "string", "width": 90},
            {"plaintext": "Path", "type": "string", "fillWidth": true},
            {"plaintext": "Status", "type": "string", "width": 80},
        ];
        let rows = [];
        for(let j = 0; j < drivers.length; j++){
            let d = drivers[j];
            rows.push({
                "Name": {"plaintext": d.name, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                "Size": {"plaintext": d.size},
                "Path": {"plaintext": d.path, "copyIcon": d.path.length > 0 && d.path !== "-", "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Status": {"plaintext": d.status},
            });
        }
        let title = summaryLine || ("Drivers \u2014 " + drivers.length + " loaded");
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
