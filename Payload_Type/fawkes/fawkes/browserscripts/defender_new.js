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
        // Detect action type from output
        if(combined.includes("Exclusions")){
            // Parse exclusion list
            let exclusions = [];
            let currentType = "";
            let lines = combined.split("\n");
            for(let line of lines){
                let typeMatch = line.match(/^\s+(Paths?|Processes?|Extensions?|IPs?):/i);
                if(typeMatch){
                    currentType = typeMatch[1];
                    continue;
                }
                let itemMatch = line.match(/^\s+-\s+(.+)/);
                if(itemMatch && currentType){
                    exclusions.push({type: currentType, value: itemMatch[1].trim()});
                }
            }
            if(exclusions.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Type", "type": "string", "width": 120},
                {"plaintext": "Exclusion", "type": "string", "fillWidth": true},
            ];
            let rows = exclusions.map(function(e){
                return {
                    "Type": {"plaintext": e.type},
                    "Exclusion": {"plaintext": e.value, "copyIcon": true},
                    "rowStyle": {},
                };
            });
            return {"table": [{"headers": headers, "rows": rows, "title": "Defender Exclusions (" + exclusions.length + ")"}]};
        }
        if(combined.includes("Defender Status") || combined.includes("registry")){
            // Parse key-value status pairs
            let fields = [];
            let lines = combined.split("\n");
            for(let line of lines){
                let kvMatch = line.match(/^\s+(\w[\w\s]*?):\s+(.+)/);
                if(kvMatch){
                    fields.push([kvMatch[1].trim(), kvMatch[2].trim()]);
                }
                // Also handle NAME=VALUE from WMI
                let eqMatch = line.match(/^(\w+)\s*=\s*(.+)/);
                if(eqMatch){
                    fields.push([eqMatch[1], eqMatch[2]]);
                }
            }
            if(fields.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Setting", "type": "string", "width": 250},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = fields.map(function(f){
                let rowStyle = {};
                let val = f[1].toLowerCase();
                // Highlight disabled protections in red
                if((f[0].includes("Disable") || f[0].includes("disable")) && (val === "1" || val === "true")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                }
                // Highlight enabled protections in green
                if((f[0].includes("Enable") || f[0].includes("enable")) && (val === "1" || val === "true")){
                    rowStyle = {"backgroundColor": "rgba(0,200,0,0.1)"};
                }
                return {
                    "Setting": {"plaintext": f[0]},
                    "Value": {"plaintext": f[1], "copyIcon": true},
                    "rowStyle": rowStyle,
                };
            });
            return {"table": [{"headers": headers, "rows": rows, "title": "Windows Defender Status"}]};
        }
        // Simple action results (add/remove exclusion, enable/disable)
        return {"plaintext": combined};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
