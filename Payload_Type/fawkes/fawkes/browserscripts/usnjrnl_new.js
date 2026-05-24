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
        // Parse query: key-value journal metadata
        if(combined.includes("Journal ID:") && !combined.includes("TIMESTAMP")){
            let fields = [];
            let lines = combined.split("\n");
            for(let line of lines){
                let kvMatch = line.match(/^\s+([\w\s]+?):\s+(.+)/);
                if(kvMatch){
                    fields.push([kvMatch[1].trim(), kvMatch[2].trim()]);
                }
            }
            if(fields.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Property", "type": "string", "width": 160},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = fields.map(function(f){
                return {
                    "Property": {"plaintext": f[0]},
                    "Value": {"plaintext": f[1], "copyIcon": true},
                    "rowStyle": {},
                };
            });
            let volMatch = combined.match(/Volume (.+)/);
            let title = "USN Journal" + (volMatch ? " — " + volMatch[1] : "");
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        // Parse recent records table: TIMESTAMP  FILENAME  REASON
        if(combined.includes("TIMESTAMP") && combined.includes("FILENAME")){
            let lines = combined.split("\n");
            let dataLines = [];
            let pastHeader = false;
            for(let line of lines){
                if(line.startsWith("---") || line.startsWith("===")){
                    pastHeader = true;
                    continue;
                }
                if(pastHeader && line.trim().length > 0){
                    // Parse fixed-width columns: 20 chars timestamp, 40 chars filename, rest is reason
                    let ts = line.substring(0, 20).trim();
                    let fn = line.substring(20, 60).trim();
                    let reason = line.substring(60).trim();
                    if(ts && fn){
                        dataLines.push({timestamp: ts, filename: fn, reason: reason});
                    }
                }
            }
            if(dataLines.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Timestamp", "type": "string", "width": 170},
                {"plaintext": "Filename", "type": "string", "fillWidth": true},
                {"plaintext": "Reason", "type": "string", "width": 250},
            ];
            let rows = dataLines.map(function(r){
                let rowStyle = {};
                let reasonLower = r.reason.toLowerCase();
                if(reasonLower.includes("delete")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
                } else if(reasonLower.includes("create") || reasonLower.includes("new")){
                    rowStyle = {"backgroundColor": "rgba(0,200,0,0.1)"};
                } else if(reasonLower.includes("rename")){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                }
                return {
                    "Timestamp": {"plaintext": r.timestamp},
                    "Filename": {"plaintext": r.filename, "copyIcon": true},
                    "Reason": {"plaintext": r.reason},
                    "rowStyle": rowStyle,
                };
            });
            let countMatch = combined.match(/Last (\d+) records/);
            let title = "USN Journal Records (" + dataLines.length + ")";
            if(countMatch) title = "USN Journal — Last " + countMatch[1] + " records";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        // Delete action or other
        return {"plaintext": combined};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
