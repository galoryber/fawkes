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
        // Parse secure delete results: [+] Securely deleted: PATH (SIZE, N passes)
        let results = combined.match(/\[[+!]\] .+/g);
        if(!results || results.length === 0){
            return {"plaintext": combined};
        }
        if(results.length === 1){
            // Single file: key-value display
            let line = results[0];
            let fields = [];
            let actionMatch = line.match(/\[.\] (Securely deleted|Wiped|MBR\/GPT wiped):\s+(.+?)(?:\s+\(|$)/);
            if(actionMatch){
                fields.push(["Action", actionMatch[1]]);
                fields.push(["Target", actionMatch[2]]);
            }
            let sizeMatch = line.match(/\((\d[\d.]+ \w+)/);
            if(sizeMatch) fields.push(["Size", sizeMatch[1]]);
            let passMatch = line.match(/(\d+) pass/);
            if(passMatch) fields.push(["Passes", passMatch[1]]);
            if(fields.length === 0) return {"plaintext": combined};
            let headers = [
                {"plaintext": "Field", "type": "string", "width": 100},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = fields.map(function(f){
                return {
                    "Field": {"plaintext": f[0]},
                    "Value": {"plaintext": f[1], "copyIcon": true},
                    "rowStyle": f[0] === "Action" ? {"backgroundColor": "rgba(255,0,0,0.1)"} : {},
                };
            });
            return {"table": [{"headers": headers, "rows": rows, "title": "Secure Delete Complete"}]};
        }
        // Multiple results (directory or batch)
        let headers = [
            {"plaintext": "Status", "type": "string", "width": 60},
            {"plaintext": "Details", "type": "string", "fillWidth": true},
        ];
        let rows = results.map(function(r){
            let isError = r.startsWith("[!]");
            return {
                "Status": {"plaintext": isError ? "WARN" : "OK"},
                "Details": {"plaintext": r.replace(/^\[[+!]\]\s*/, "")},
                "rowStyle": isError ? {"backgroundColor": "rgba(255,165,0,0.15)"} : {"backgroundColor": "rgba(0,200,0,0.05)"},
            };
        });
        return {"table": [{"headers": headers, "rows": rows, "title": "Secure Delete (" + rows.length + " operations)"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
