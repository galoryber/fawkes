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

        // Monitor action returns an object with a .captured array
        if(data && typeof data === "object" && !Array.isArray(data) && data.captured !== undefined){
            let result = [];
            // Summary header
            let summary = data.message || ("Captured " + data.total + " TGT(s)");
            let summaryColor = data.total > 0 ? "rgba(0,200,0,0.12)" : "rgba(255,165,0,0.1)";
            result.push({
                "plaintext": "Monitor Summary: " + summary,
                "backgroundColor": summaryColor,
            });
            if(!data.captured || data.captured.length === 0){
                return {
                    "plaintext": summary + "\n\nNo TGTs captured during the monitoring window.",
                };
            }
            let headers = [
                {"plaintext": "captured_at", "type": "string", "width": 160},
                {"plaintext": "client", "type": "string", "width": 220, "fillWidth": false},
                {"plaintext": "server", "type": "string", "width": 220},
                {"plaintext": "luid", "type": "string", "width": 140},
                {"plaintext": "valid_until", "type": "string", "width": 140},
                {"plaintext": "kirbi_b64", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < data.captured.length; j++){
                let t = data.captured[j];
                rows.push({
                    "captured_at": {"plaintext": t.captured_at || "-"},
                    "client": {"plaintext": t.client || "-", "copyIcon": true},
                    "server": {"plaintext": t.server || "-"},
                    "luid": {"plaintext": t.luid || "-"},
                    "valid_until": {"plaintext": t.end_time || "-"},
                    "kirbi_b64": {"plaintext": t.kirbi_b64 || "-", "copyIcon": true},
                    "rowStyle": {"backgroundColor": "rgba(0,200,0,0.1)"},
                });
            }
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Captured TGTs (" + data.captured.length + ") — " + summary,
                }]
            };
        }

        // LDAP enumeration actions return an array of delegation entries
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No delegation configurations found"};
        }
        let headers = [
            {"plaintext": "account", "type": "string", "width": 180},
            {"plaintext": "delegation_type", "type": "string", "width": 120},
            {"plaintext": "mode", "type": "string", "width": 160},
            {"plaintext": "targets", "type": "string", "fillWidth": true},
            {"plaintext": "risk", "type": "string", "width": 250},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.delegation_type === "Unconstrained"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.s4u2self){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            } else if(e.delegation_type === "Protected"){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.08)"};
            }
            if(e.disabled){
                rowStyle = {"backgroundColor": "rgba(128,128,128,0.15)"};
            }
            let targetsStr = "-";
            if(e.targets && e.targets.length > 0){
                targetsStr = e.targets.join(", ");
            }
            let acctDisplay = e.account || "-";
            if(e.disabled){
                acctDisplay += " [DISABLED]";
            }
            rows.push({
                "account": {"plaintext": acctDisplay, "copyIcon": true},
                "delegation_type": {"plaintext": e.delegation_type || "-"},
                "mode": {"plaintext": e.mode || "-"},
                "targets": {"plaintext": targetsStr},
                "risk": {"plaintext": e.risk || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Kerberos Delegation (" + data.length + " entries)",
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
