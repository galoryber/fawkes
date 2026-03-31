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
        if(!combined.includes("potential secrets")){
            return {"plaintext": combined};
        }
        // Parse: [Type] File:Line\n  Preview
        let lines = combined.split("\n");
        let findings = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            // Match: [SecretType] path/to/file:123
            let m = line.match(/^\[(.+?)\]\s+(.+?):(\d+)$/);
            if(m){
                let preview = "";
                // Next line is the preview (indented)
                if(i + 1 < lines.length && lines[i + 1].match(/^\s+/)){
                    preview = lines[i + 1].trim();
                }
                findings.push({
                    type: m[1],
                    file: m[2],
                    line: m[3],
                    preview: preview,
                });
            }
        }
        if(findings.length === 0){
            return {"plaintext": combined};
        }
        // Categorize severity by type
        let highSeverity = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN", "PRIVATE_KEY", "PASSWORD", "API_KEY", "BEARER_TOKEN"];
        let medSeverity = ["SLACK_TOKEN", "SLACK_WEBHOOK", "GENERIC_SECRET", "CONNECTION_STRING"];

        let headers = [
            {"plaintext": "Type", "type": "string", "width": 180},
            {"plaintext": "File", "type": "string", "fillWidth": true},
            {"plaintext": "Line", "type": "number", "width": 70},
            {"plaintext": "Preview", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < findings.length; j++){
            let f = findings[j];
            let rowStyle = {};
            let typeUpper = f.type.toUpperCase().replace(/[\s-]/g, "_");
            if(highSeverity.some(s => typeUpper.includes(s))){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
            } else if(medSeverity.some(s => typeUpper.includes(s))){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
            }
            rows.push({
                "Type": {"plaintext": f.type, "cellStyle": {"fontWeight": "bold"}},
                "File": {"plaintext": f.file, "copyIcon": true},
                "Line": {"plaintext": f.line},
                "Preview": {"plaintext": f.preview, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "rowStyle": rowStyle,
            });
        }
        // Count header
        let countMatch = combined.match(/Found (\d+) potential/);
        let count = countMatch ? countMatch[1] : findings.length;
        let truncated = combined.includes("results truncated") ? " (truncated)" : "";
        let title = "Secret Scan: " + count + " findings" + truncated;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
