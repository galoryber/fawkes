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
        // Try to parse as JSON for structured registry data
        let data;
        try {
            data = JSON.parse(combined);
        } catch(e) {
            // Non-JSON output — render as plaintext
            return {"plaintext": combined};
        }

        // Handle single object with key + values array
        if(!Array.isArray(data) && typeof data === "object" && data !== null){
            if(data.key && Array.isArray(data.values)){
                // Single key with values
                let headers = [
                    {"plaintext": "Value Name", "type": "string", "width": 250},
                    {"plaintext": "Value Type", "type": "string", "width": 150},
                    {"plaintext": "Value Data", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                for(let v = 0; v < data.values.length; v++){
                    let val = data.values[v];
                    let dataStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
                    rows.push({
                        "Value Name": {"plaintext": val.name || "(Default)", "copyIcon": true},
                        "Value Type": {"plaintext": val.type || "N/A"},
                        "Value Data": {"plaintext": val.data !== undefined ? String(val.data) : "", "copyIcon": true, "cellStyle": dataStyle},
                    });
                }
                return {
                    "table": [{
                        "headers": headers,
                        "rows": rows,
                        "title": "Remote Registry \u2014 " + (data.key || "Unknown Key") + " (" + data.values.length + " values)",
                    }]
                };
            }
            // Single object without values array — show as plaintext
            return {"plaintext": combined};
        }

        // Handle array of registry entries
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": combined};
        }

        // Check if entries have a 'values' sub-array (multiple keys with values)
        if(data[0].key && Array.isArray(data[0].values)){
            let headers = [
                {"plaintext": "Key Path", "type": "string", "fillWidth": true},
                {"plaintext": "Value Name", "type": "string", "width": 200},
                {"plaintext": "Value Type", "type": "string", "width": 130},
                {"plaintext": "Value Data", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            let totalValues = 0;
            for(let j = 0; j < data.length; j++){
                let entry = data[j];
                let keyPath = entry.key || "Unknown";
                let values = entry.values || [];
                for(let v = 0; v < values.length; v++){
                    let val = values[v];
                    let keyStyle = {};
                    let dataStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
                    // Highlight security-relevant paths
                    let lowerPath = keyPath.toLowerCase();
                    if(lowerPath.includes("run") || lowerPath.includes("startup") || lowerPath.includes("services")){
                        keyStyle = {"color": "#e67e22", "fontWeight": "bold"};
                    }
                    if(lowerPath.includes("policies") || lowerPath.includes("security")){
                        keyStyle = {"color": "#3498db", "fontWeight": "bold"};
                    }
                    rows.push({
                        "Key Path": {"plaintext": keyPath, "copyIcon": true, "cellStyle": keyStyle},
                        "Value Name": {"plaintext": val.name || "(Default)", "copyIcon": true},
                        "Value Type": {"plaintext": val.type || "N/A"},
                        "Value Data": {"plaintext": val.data !== undefined ? String(val.data) : "", "copyIcon": true, "cellStyle": dataStyle},
                    });
                    totalValues++;
                }
            }
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Remote Registry \u2014 " + data.length + " keys, " + totalValues + " values",
                }]
            };
        }

        // Flat array of key/value entries (like reg_new.js format)
        let headers = [
            {"plaintext": "Key Path", "type": "string", "fillWidth": true},
            {"plaintext": "Value Name", "type": "string", "width": 200},
            {"plaintext": "Value Data", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let keyStyle = {};
            let dataStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
            let lowerPath = (e.key_path || e.key || "").toLowerCase();
            if(lowerPath.includes("run") || lowerPath.includes("startup") || lowerPath.includes("services")){
                keyStyle = {"color": "#e67e22", "fontWeight": "bold"};
            }
            if(lowerPath.includes("policies") || lowerPath.includes("security")){
                keyStyle = {"color": "#3498db", "fontWeight": "bold"};
            }
            rows.push({
                "Key Path": {"plaintext": e.key_path || e.key || "", "copyIcon": true, "cellStyle": keyStyle},
                "Value Name": {"plaintext": e.value_name || e.name || "(Default)", "copyIcon": true},
                "Value Data": {"plaintext": e.value_data || e.data || "", "copyIcon": true, "cellStyle": dataStyle},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Remote Registry \u2014 " + data.length + " entries",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
