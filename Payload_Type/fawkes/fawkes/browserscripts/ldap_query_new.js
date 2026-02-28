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
        // Detect DACL mode vs regular query
        if(data.mode === "dacl"){
            // DACL output
            let riskColors = {
                "dangerous": "rgba(255,0,0,0.2)",
                "notable": "rgba(255,165,0,0.15)",
                "standard": "rgba(255,255,255,0)",
            };
            let headers = [
                {"plaintext": "principal", "type": "string", "fillWidth": true},
                {"plaintext": "permissions", "type": "string", "fillWidth": true},
                {"plaintext": "risk", "type": "string", "width": 100},
                {"plaintext": "sid", "type": "string", "width": 200},
            ];
            let rows = [];
            if(data.aces){
                for(let j = 0; j < data.aces.length; j++){
                    let ace = data.aces[j];
                    let rowStyle = {};
                    if(riskColors[ace.risk] !== undefined){
                        rowStyle = {"backgroundColor": riskColors[ace.risk]};
                    }
                    rows.push({
                        "principal": {"plaintext": ace.principal, "copyIcon": true},
                        "permissions": {"plaintext": ace.permissions},
                        "risk": {"plaintext": ace.risk},
                        "sid": {"plaintext": ace.sid, "copyIcon": true},
                        "rowStyle": rowStyle,
                    });
                }
            }
            let title = "DACL — " + data.target;
            if(data.dangerous > 0){
                title += " (" + data.dangerous + " dangerous)";
            }
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        } else if(data.entries !== undefined){
            // Regular LDAP query
            if(!Array.isArray(data.entries) || data.entries.length === 0){
                return {"plaintext": "No results for: " + (data.query || "query")};
            }
            // Collect all attribute names across entries for dynamic columns
            let attrSet = {};
            attrSet["dn"] = true;
            for(let j = 0; j < data.entries.length; j++){
                let entry = data.entries[j];
                for(let key in entry){
                    if(entry.hasOwnProperty(key)){
                        attrSet[key] = true;
                    }
                }
            }
            // Build ordered headers: dn first, then sAMAccountName if present, then rest sorted
            let attrOrder = ["dn"];
            let priorityAttrs = ["sAMAccountName", "cn", "displayName", "userPrincipalName", "dNSHostName", "description"];
            for(let k = 0; k < priorityAttrs.length; k++){
                if(attrSet[priorityAttrs[k]]){
                    attrOrder.push(priorityAttrs[k]);
                    delete attrSet[priorityAttrs[k]];
                }
            }
            delete attrSet["dn"];
            let remaining = Object.keys(attrSet).sort();
            attrOrder = attrOrder.concat(remaining);

            let headers = [];
            for(let k = 0; k < attrOrder.length; k++){
                let attr = attrOrder[k];
                let hdr = {"plaintext": attr, "type": "string"};
                if(attr === "dn"){
                    hdr["fillWidth"] = true;
                } else if(attr === "sAMAccountName" || attr === "cn"){
                    hdr["width"] = 150;
                } else {
                    hdr["fillWidth"] = true;
                }
                headers.push(hdr);
            }
            let rows = [];
            for(let j = 0; j < data.entries.length; j++){
                let entry = data.entries[j];
                let row = {};
                for(let k = 0; k < attrOrder.length; k++){
                    let attr = attrOrder[k];
                    let val = entry[attr] !== undefined ? String(entry[attr]) : "";
                    // Remove surrounding quotes from JSON string values
                    if(val.startsWith('"') && val.endsWith('"')){
                        val = val.slice(1, -1);
                    }
                    row[attr] = {"plaintext": val};
                    if(attr === "sAMAccountName" || attr === "dn"){
                        row[attr]["copyIcon"] = true;
                    }
                }
                rows.push(row);
            }
            let title = (data.query || "LDAP Query") + " — " + data.count + " result(s)";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        // Fallback
        return {"plaintext": combined};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
