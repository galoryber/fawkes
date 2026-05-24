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
        } else if(data.summary !== undefined && data.summary.domain !== undefined){
            // BloodHound CE collection output
            let s = data.summary;
            let summaryHeaders = [
                {"plaintext": "Category", "type": "string", "width": 150},
                {"plaintext": "Count", "type": "number", "width": 100},
            ];
            let summaryRows = [
                {"Category": {"plaintext": "Domain"}, "Count": {"plaintext": s.domain}},
                {"Category": {"plaintext": "Domain SID"}, "Count": {"plaintext": s.domain_sid}},
                {"Category": {"plaintext": "Users"}, "Count": {"plaintext": String(s.users)}},
                {"Category": {"plaintext": "Computers"}, "Count": {"plaintext": String(s.computers)}},
                {"Category": {"plaintext": "Groups"}, "Count": {"plaintext": String(s.groups)}},
                {"Category": {"plaintext": "OUs"}, "Count": {"plaintext": String(s.ous)}},
                {"Category": {"plaintext": "GPOs"}, "Count": {"plaintext": String(s.gpos)}},
                {"Category": {"plaintext": "Trusts"}, "Count": {"plaintext": String(s.trusts)}},
            ];
            let tables = [{"headers": summaryHeaders, "rows": summaryRows, "title": "BloodHound CE Collection — " + s.domain}];

            // Users table (top 50)
            if(data.users && data.users.data && data.users.data.length > 0){
                let uHeaders = [
                    {"plaintext": "Name", "type": "string", "fillWidth": true},
                    {"plaintext": "SID", "type": "string", "width": 300},
                    {"plaintext": "Enabled", "type": "string", "width": 70},
                    {"plaintext": "AdminCount", "type": "string", "width": 90},
                    {"plaintext": "HasSPN", "type": "string", "width": 70},
                    {"plaintext": "Preauth", "type": "string", "width": 70},
                ];
                let uRows = [];
                let limit = Math.min(data.users.data.length, 50);
                for(let j = 0; j < limit; j++){
                    let u = data.users.data[j];
                    let p = u.Properties || {};
                    let rowStyle = {};
                    if(p.admincount) rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                    if(p.dontreqpreauth) rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                    uRows.push({
                        "Name": {"plaintext": p.name || "", "copyIcon": true},
                        "SID": {"plaintext": u.ObjectIdentifier || "", "copyIcon": true},
                        "Enabled": {"plaintext": p.enabled ? "yes" : "no"},
                        "AdminCount": {"plaintext": p.admincount ? "YES" : ""},
                        "HasSPN": {"plaintext": p.hasspn ? "YES" : ""},
                        "Preauth": {"plaintext": p.dontreqpreauth ? "NO" : "yes"},
                        "rowStyle": rowStyle,
                    });
                }
                let uTitle = "Users (" + data.users.data.length + ")";
                if(data.users.data.length > 50) uTitle += " — showing first 50";
                tables.push({"headers": uHeaders, "rows": uRows, "title": uTitle});
            }

            // Computers table
            if(data.computers && data.computers.data && data.computers.data.length > 0){
                let cHeaders = [
                    {"plaintext": "Name", "type": "string", "fillWidth": true},
                    {"plaintext": "OS", "type": "string", "width": 200},
                    {"plaintext": "SID", "type": "string", "width": 300},
                    {"plaintext": "Enabled", "type": "string", "width": 70},
                    {"plaintext": "Unconstr.", "type": "string", "width": 80},
                    {"plaintext": "LAPS", "type": "string", "width": 60},
                ];
                let cRows = [];
                for(let j = 0; j < data.computers.data.length; j++){
                    let c = data.computers.data[j];
                    let p = c.Properties || {};
                    let rowStyle = {};
                    if(p.unconstraineddelegation) rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                    cRows.push({
                        "Name": {"plaintext": p.name || "", "copyIcon": true},
                        "OS": {"plaintext": p.operatingsystem || ""},
                        "SID": {"plaintext": c.ObjectIdentifier || "", "copyIcon": true},
                        "Enabled": {"plaintext": p.enabled ? "yes" : "no"},
                        "Unconstr.": {"plaintext": p.unconstraineddelegation ? "YES" : ""},
                        "LAPS": {"plaintext": p.haslaps ? "yes" : ""},
                        "rowStyle": rowStyle,
                    });
                }
                tables.push({"headers": cHeaders, "rows": cRows, "title": "Computers (" + data.computers.data.length + ")"});
            }

            // Trusts table
            if(data.domains && data.domains.data && data.domains.data.length > 0){
                let d = data.domains.data[0];
                if(d.Trusts && d.Trusts.length > 0){
                    let tHeaders = [
                        {"plaintext": "Target Domain", "type": "string", "fillWidth": true},
                        {"plaintext": "Target SID", "type": "string", "width": 300},
                        {"plaintext": "Direction", "type": "string", "width": 100},
                        {"plaintext": "Transitive", "type": "string", "width": 80},
                        {"plaintext": "SID Filter", "type": "string", "width": 80},
                    ];
                    let tRows = [];
                    let dirNames = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"};
                    for(let j = 0; j < d.Trusts.length; j++){
                        let tr = d.Trusts[j];
                        tRows.push({
                            "Target Domain": {"plaintext": tr.TargetDomainName || "", "copyIcon": true},
                            "Target SID": {"plaintext": tr.TargetDomainSid || ""},
                            "Direction": {"plaintext": dirNames[tr.TrustDirection] || String(tr.TrustDirection)},
                            "Transitive": {"plaintext": tr.IsTransitive ? "yes" : "no"},
                            "SID Filter": {"plaintext": tr.SidFilteringEnabled ? "yes" : "no"},
                        });
                    }
                    tables.push({"headers": tHeaders, "rows": tRows, "title": "Domain Trusts"});
                }
            }

            return {"table": tables};
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
