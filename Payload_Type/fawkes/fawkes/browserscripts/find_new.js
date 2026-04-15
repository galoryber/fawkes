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
        // Parse text table format: "SIZE  DATE  PATH"
        let lines = combined.split("\n");
        let entries = [];
        for(let line of lines){
            line = line.trim();
            // Match: "1.2 KB       2026-01-15 12:30 /path/to/file"
            // or:    "<DIR>        2026-01-15 12:30 /path/to/dir"
            let m = line.match(/^(\S+(?:\s+\S+)?)\s{2,}(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+(.+)$/);
            if(m){
                entries.push({
                    size: m[1].trim(),
                    modified: m[2].trim(),
                    path: m[3].trim(),
                    isDir: m[1].trim() === "<DIR>"
                });
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "size", "type": "string", "width": 90},
            {"plaintext": "modified", "type": "string", "width": 130},
            {"plaintext": "path", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let e of entries){
            let rowStyle = {};
            let path = e.path.toLowerCase();
            // Color directories blue, credential files red, config files orange
            if(e.isDir){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.12)"};
            } else if(path.match(/\.(pem|key|ppk|pfx|p12|kdbx|kdb|pgpass|netrc|shadow|htpasswd)/)){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(path.match(/\.(conf|cfg|ini|yaml|yml|json|xml|env|toml|properties)/)){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.12)"};
            }
            rows.push({
                "size": {"plaintext": e.size},
                "modified": {"plaintext": e.modified},
                "path": {"plaintext": e.path, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        // Extract summary from first lines
        let summaryMatch = combined.match(/Found (\d+) match/);
        let title = summaryMatch ? "Find — " + summaryMatch[1] + " matches" : "Find — " + entries.length + " results";
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
