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
        // readmemory returns hex bytes or address-based hex dump
        // Parse metadata if present
        let fields = [];
        let pidMatch = combined.match(/PID[:\s]+(\d+)/i);
        let addrMatch = combined.match(/Address[:\s]+(0x[\da-fA-F]+)/i);
        let sizeMatch = combined.match(/Size[:\s]+(\d+)/i);
        if(pidMatch) fields.push(["PID", pidMatch[1]]);
        if(addrMatch) fields.push(["Address", addrMatch[1]]);
        if(sizeMatch) fields.push(["Size", sizeMatch[1] + " bytes"]);
        if(fields.length > 0){
            let headers = [
                {"plaintext": "Field", "type": "string", "width": 100},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = fields.map(function(f){
                return {
                    "Field": {"plaintext": f[0]},
                    "Value": {"plaintext": f[1], "copyIcon": true},
                    "rowStyle": {},
                };
            });
            return {"table": [{"headers": headers, "rows": rows, "title": "Memory Read"}]};
        }
        return {"plaintext": combined};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
