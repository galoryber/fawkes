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
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "dll", "type": "string", "width": 120},
            {"plaintext": "function", "type": "string", "fillWidth": true},
            {"plaintext": "loaded", "type": "string", "width": 70},
            {"plaintext": "found", "type": "string", "width": 70},
            {"plaintext": "patchable", "type": "string", "width": 90},
            {"plaintext": "already_patched", "type": "string", "width": 110},
            {"plaintext": "strategy", "type": "string", "width": 100},
            {"plaintext": "current_bytes", "type": "string", "width": 180},
        ];
        let rows = [];
        let patchable = 0;
        let patched = 0;
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            if(e.patchable) patchable++;
            if(e.already_patched) patched++;
            let rowStyle = {};
            if(e.already_patched){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.12)"};
            } else if(e.patchable){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.12)"};
            } else if(!e.loaded || !e.found){
                rowStyle = {"backgroundColor": "rgba(200,200,200,0.12)"};
            }
            rows.push({
                "dll": {"plaintext": e.dll},
                "function": {"plaintext": e.function},
                "loaded": {"plaintext": e.loaded ? "Yes" : "No"},
                "found": {"plaintext": e.found ? "Yes" : "No"},
                "patchable": {"plaintext": e.patchable ? "Yes" : "No"},
                "already_patched": {"plaintext": e.already_patched ? "PATCHED" : "-"},
                "strategy": {"plaintext": e.default_strategy || "-"},
                "current_bytes": {"plaintext": e.current_bytes || "-", "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "AMSI/ETW Scan — " + data.length + " targets, " + patchable + " patchable, " + patched + " already patched",
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
