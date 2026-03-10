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
        let parsed = JSON.parse(combined);

        // Support both old format (array) and new format (object with trusts/forest)
        let data;
        let forestInfo = null;
        if(Array.isArray(parsed)){
            data = parsed;
        } else {
            data = parsed.trusts || [];
            forestInfo = parsed.forest || null;
        }

        let tables = [];

        // Forest topology table if available
        if(forestInfo && forestInfo.forest_root){
            let forestHeaders = [
                {"plaintext": "property", "type": "string", "width": 150},
                {"plaintext": "value", "type": "string", "fillWidth": true},
            ];
            let forestRows = [
                {
                    "property": {"plaintext": "Forest Root"},
                    "value": {"plaintext": forestInfo.forest_root, "copyIcon": true},
                },
            ];
            if(forestInfo.domains && forestInfo.domains.length > 0){
                forestRows.push({
                    "property": {"plaintext": "Domains"},
                    "value": {"plaintext": forestInfo.domains.join(", "), "copyIcon": true},
                });
                forestRows.push({
                    "property": {"plaintext": "Domain Count"},
                    "value": {"plaintext": String(forestInfo.domains.length)},
                });
            }
            tables.push({
                "headers": forestHeaders,
                "rows": forestRows,
                "title": "Forest Topology",
            });
        }

        if(data.length === 0 && tables.length === 0){
            return {"plaintext": "No trust relationships found"};
        }

        if(data.length > 0){
            let headers = [
                {"plaintext": "partner", "type": "string", "width": 200},
                {"plaintext": "direction", "type": "string", "width": 260},
                {"plaintext": "category", "type": "string", "width": 110},
                {"plaintext": "transitive", "type": "string", "width": 160},
                {"plaintext": "attributes", "type": "string", "width": 200},
                {"plaintext": "created", "type": "string", "width": 140},
                {"plaintext": "risk", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                let rowStyle = {};
                if(e.risk && !e.risk.includes("Selective authentication")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                } else if(e.direction && e.direction.startsWith("Bidirectional")){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.10)"};
                }
                rows.push({
                    "partner": {"plaintext": e.partner || "-", "copyIcon": true},
                    "direction": {"plaintext": e.direction || "-"},
                    "category": {"plaintext": e.category || "-"},
                    "transitive": {"plaintext": e.transitive || "-"},
                    "attributes": {"plaintext": e.attributes || "-"},
                    "created": {"plaintext": e.when_created || "-"},
                    "risk": {"plaintext": e.risk || "-"},
                    "rowStyle": rowStyle,
                });
            }
            tables.push({
                "headers": headers,
                "rows": rows,
                "title": "Domain Trusts (" + data.length + " found)",
            });
        }

        return {"table": tables};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
