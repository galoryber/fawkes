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
        let summary = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^-{4,}/) || trimmed.startsWith("Size")) continue;
            // Summary line: "[*] /path — 5.2 GB total, 1234 files"
            let sumMatch = trimmed.match(/^\[\*\]\s+(.*)/);
            if(sumMatch){
                summary = sumMatch[1];
                continue;
            }
            // Size + path: "  1.2 GB  /var/log/apache2"
            let match = trimmed.match(/^([\d.]+\s*\S+)\s+(.*)/);
            if(match){
                entries.push({size: match[1].trim(), path: match[2].trim()});
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Size", "type": "string", "width": 120},
            {"plaintext": "Path", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let sizeStyle = {};
            // Highlight large entries
            if(e.size.includes("GB") || e.size.includes("TB")){
                sizeStyle = {"fontWeight": "bold", "color": "#d94f00"};
            } else if(e.size.includes("MB")){
                let numMatch = e.size.match(/([\d.]+)/);
                if(numMatch && parseFloat(numMatch[1]) > 100){
                    sizeStyle = {"fontWeight": "bold"};
                }
            }
            rows.push({
                "Size": {"plaintext": e.size, "cellStyle": sizeStyle},
                "Path": {"plaintext": e.path, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}
            });
        }
        let title = summary ? "Disk Usage \u2014 " + summary : "Disk Usage \u2014 " + entries.length + " entries";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
