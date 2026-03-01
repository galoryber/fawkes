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
        // domaininfo returns an object, not an array
        if(!Array.isArray(data)){
            // Format domaininfo as key-value pairs
            let headers = [
                {"plaintext": "field", "type": "string", "width": 200},
                {"plaintext": "value", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            let fields = [
                ["DC Name", data.dc_name],
                ["DC Address", data.dc_address],
                ["Domain", data.domain],
                ["Forest", data.forest],
                ["DC Site", data.dc_site],
                ["Client Site", data.client_site],
                ["Min Password Length", data.min_password_length],
                ["Max Password Age (days)", data.max_password_age_days],
                ["Min Password Age (days)", data.min_password_age_days],
                ["Password History Length", data.password_history_length],
                ["Force Logoff", data.force_logoff],
            ];
            for(let f of fields){
                if(f[1] !== undefined && f[1] !== "" && f[1] !== 0){
                    rows.push({
                        "field": {"plaintext": f[0]},
                        "value": {"plaintext": String(f[1]), "copyIcon": true},
                    });
                }
            }
            let tables = [{"headers": headers, "rows": rows, "title": "Domain Info"}];
            // Add trusts table if present
            if(data.trusts && data.trusts.length > 0){
                let trustHeaders = [
                    {"plaintext": "name", "type": "string", "fillWidth": true},
                    {"plaintext": "dns", "type": "string", "fillWidth": true},
                    {"plaintext": "flags", "type": "string", "fillWidth": true},
                ];
                let trustRows = [];
                for(let t of data.trusts){
                    trustRows.push({
                        "name": {"plaintext": t.name, "copyIcon": true},
                        "dns": {"plaintext": t.dns || ""},
                        "flags": {"plaintext": t.flags || ""},
                    });
                }
                tables.push({"headers": trustHeaders, "rows": trustRows, "title": "Domain Trusts (" + data.trusts.length + ")"});
            }
            return {"table": tables};
        }
        if(data.length === 0){
            return {"plaintext": "No results found"};
        }
        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "type", "type": "string", "width": 120},
            {"plaintext": "comment", "type": "string", "fillWidth": true},
            {"plaintext": "source", "type": "string", "width": 160},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            rows.push({
                "name": {"plaintext": e.name, "copyIcon": true},
                "type": {"plaintext": e.type || ""},
                "comment": {"plaintext": e.comment || ""},
                "source": {"plaintext": e.source || ""},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Net Enum (" + data.length + " entries)",
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
