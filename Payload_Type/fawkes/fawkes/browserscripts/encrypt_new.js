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
        let data = JSON.parse(combined);
        if(!Array.isArray(data)){
            // Single object or non-array — may be encrypt/decrypt result
            if(typeof data === "object" && data !== null){
                let fields = [];
                for(let k in data){
                    fields.push([k, String(data[k])]);
                }
                let headers = [
                    {"plaintext": "field", "type": "string", "width": 140},
                    {"plaintext": "value", "type": "string", "fillWidth": true},
                ];
                let rows = fields.map(f => ({
                    "field": {"plaintext": f[0]},
                    "value": {"plaintext": f[1], "copyIcon": true},
                }));
                return {"table": [{"headers": headers, "rows": rows, "title": "Encryption Result"}]};
            }
            return {"plaintext": combined};
        }
        // Array of corrupt results
        let headers = [
            {"plaintext": "path", "type": "string", "fillWidth": true},
            {"plaintext": "original_size", "type": "number", "width": 110},
            {"plaintext": "bytes_corrupted", "type": "number", "width": 120},
            {"plaintext": "method", "type": "string", "width": 120},
        ];
        let rows = [];
        let totalCorrupted = 0;
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            totalCorrupted += e.bytes_corrupted || 0;
            rows.push({
                "path": {"plaintext": e.path, "copyIcon": true},
                "original_size": {"plaintext": String(e.original_size)},
                "bytes_corrupted": {"plaintext": String(e.bytes_corrupted)},
                "method": {"plaintext": e.method || "random"},
                "rowStyle": {"backgroundColor": "rgba(255,0,0,0.08)"},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "File Corruption — " + data.length + " files, " + totalCorrupted + " bytes corrupted",
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
