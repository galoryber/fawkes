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
        let findings = [];
        let i = 0;
        while(i < lines.length){
            let line = lines[i].trim();
            // Match: [Type] /path/to/file:123
            let m = line.match(/^\[(.+?)\]\s+(.+):(\d+)$/);
            if(m){
                let type = m[1];
                let file = m[2];
                let lineNum = m[3];
                let preview = "";
                // Next line is indented preview
                if(i + 1 < lines.length && lines[i + 1].match(/^\s{2,}/)){
                    preview = lines[i + 1].trim();
                    i++;
                }
                findings.push({type: type, file: file, line: lineNum, preview: preview});
            }
            i++;
        }
        if(findings.length === 0){
            return {"plaintext": combined};
        }
        let typeColors = {
            "AWS Access Key": "rgba(255,165,0,0.15)",
            "Private Key": "rgba(255,0,0,0.12)",
            "GitHub Token": "rgba(128,0,255,0.1)",
            "Generic API Key": "rgba(0,150,255,0.1)",
            "Password": "rgba(255,0,0,0.12)",
        };
        let headers = [
            {"plaintext": "Type", "type": "string", "width": 160},
            {"plaintext": "File", "type": "string", "fillWidth": true},
            {"plaintext": "Line", "type": "number", "width": 60},
            {"plaintext": "Preview", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < findings.length; j++){
            let f = findings[j];
            let bg = "rgba(255,200,0,0.08)";
            for(let key in typeColors){
                if(f.type.toLowerCase().includes(key.toLowerCase())){
                    bg = typeColors[key];
                    break;
                }
            }
            rows.push({
                "Type": {"plaintext": f.type, "cellStyle": {"fontWeight": "bold"}},
                "File": {"plaintext": f.file, "copyIcon": true},
                "Line": {"plaintext": f.line},
                "Preview": {"plaintext": f.preview, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                "rowStyle": {"backgroundColor": bg},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Secret Scan \u2014 " + findings.length + " findings",
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
