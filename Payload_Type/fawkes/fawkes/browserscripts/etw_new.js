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
        // "sessions" action: parse session table
        if(combined.includes("Active ETW Trace Sessions")){
            let lines = combined.split("\n");
            let sessions = [];
            let pastHeader = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.match(/^-{10,}$/)){
                    pastHeader = true;
                    continue;
                }
                if(!pastHeader || trimmed.length === 0) continue;
                // Parse: "SessionName                         events   Security Relevance"
                let parts = trimmed.split(/\s{2,}/);
                if(parts.length >= 1){
                    let name = parts[0].trim();
                    let events = parts.length >= 2 ? parts[1].trim() : "";
                    let relevance = parts.length >= 3 ? parts.slice(2).join(" ").trim() : "";
                    sessions.push({name: name, events: events, relevance: relevance});
                }
            }
            if(sessions.length > 0){
                let headers = [
                    {"plaintext": "Session Name", "type": "string", "fillWidth": true},
                    {"plaintext": "Events", "type": "string", "width": 80},
                    {"plaintext": "Security Relevance", "type": "string", "width": 300},
                ];
                let rows = [];
                let securityKeywords = ["Defender", "Security", "Sysmon", "ETW", "Audit", "Threat", "Detection", "AMSI", "Antimalware"];
                for(let j = 0; j < sessions.length; j++){
                    let s = sessions[j];
                    let isSecurityRelevant = securityKeywords.some(function(kw){ return s.name.toLowerCase().includes(kw.toLowerCase()) || s.relevance.toLowerCase().includes(kw.toLowerCase()); });
                    rows.push({
                        "Session Name": {"plaintext": s.name, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                        "Events": {"plaintext": s.events},
                        "Security Relevance": {"plaintext": s.relevance, "cellStyle": isSecurityRelevant ? {"color": "#d32f2f", "fontWeight": "bold"} : {}},
                        "rowStyle": isSecurityRelevant ? {"backgroundColor": "rgba(255,0,0,0.08)"} : {},
                    });
                }
                let countMatch = combined.match(/(\d+)\s+found/);
                let count = countMatch ? countMatch[1] : sessions.length;
                return {"table": [{"headers": headers, "rows": rows, "title": "ETW Trace Sessions — " + count + " active"}]};
            }
        }
        // "providers" or "provider-list" action: parse provider list
        if(combined.includes("ETW Providers")){
            let lines = combined.split("\n");
            let providers = [];
            let pastHeader = false;
            let isSecuritySection = false;
            let hasCategory = combined.includes("CATEGORY"); // provider-list has category column
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.includes("Security-Relevant Providers")){
                    isSecuritySection = true;
                    continue;
                }
                if(trimmed.includes("other (non-security) providers")){
                    isSecuritySection = false;
                    continue;
                }
                if(trimmed.match(/^-{10,}$/)){
                    pastHeader = true;
                    continue;
                }
                if(!pastHeader || trimmed.length === 0) continue;
                if(trimmed.startsWith("PROVIDER") || trimmed.startsWith("Name")) continue;
                // Session detail lines (from provider-list)
                if(trimmed.startsWith("└─")){
                    if(providers.length > 0){
                        let detailMatch = trimmed.match(/Session\s+(\d+):\s+level=(\w+)\s+keywords=(\S+)/);
                        if(detailMatch){
                            if(!providers[providers.length-1].sessions) providers[providers.length-1].sessions = [];
                            providers[providers.length-1].sessions.push({id: detailMatch[1], level: detailMatch[2], keywords: detailMatch[3]});
                        }
                    }
                    continue;
                }
                // Parse provider lines (2 formats: old providers and new provider-list)
                let parts = trimmed.split(/\s{2,}/);
                if(hasCategory && parts.length >= 4){
                    providers.push({name: parts[0].trim(), category: parts[1].trim(), active: parts[2].trim(), guid: parts[3].trim(), security: true, sessions: []});
                } else if(parts.length >= 2){
                    providers.push({name: parts[0].trim(), guid: parts[1].trim(), security: isSecuritySection, sessions: []});
                } else if(trimmed.length > 0){
                    providers.push({name: trimmed, guid: "", security: isSecuritySection, sessions: []});
                }
            }
            if(providers.length > 0){
                let headers;
                if(hasCategory){
                    headers = [
                        {"plaintext": "Provider Name", "type": "string", "fillWidth": true},
                        {"plaintext": "Category", "type": "string", "width": 100},
                        {"plaintext": "Active", "type": "string", "width": 80},
                        {"plaintext": "GUID", "type": "string", "width": 300},
                        {"plaintext": "Sessions", "type": "string", "width": 250},
                    ];
                } else {
                    headers = [
                        {"plaintext": "Provider Name", "type": "string", "fillWidth": true},
                        {"plaintext": "GUID", "type": "string", "width": 300},
                    ];
                }
                let rows = [];
                let categoryColors = {"Kernel": "#1565c0", "EDR": "#d32f2f", "AV/AMSI": "#d32f2f", "Audit": "#e65100", "Runtime": "#2e7d32", "Remote": "#6a1b9a", "Network": "#00838f", "Auth": "#ef6c00", "Sched": "#5d4037"};
                for(let j = 0; j < providers.length; j++){
                    let p = providers[j];
                    let isActive = p.active && p.active.startsWith("yes");
                    let isDangerous = p.category && (p.category === "EDR" || p.category === "AV/AMSI");
                    let row;
                    if(hasCategory){
                        let catColor = categoryColors[p.category] || "#616161";
                        let sessionStr = (p.sessions || []).map(function(s){ return "S" + s.id + "(" + s.level + ")"; }).join(", ");
                        row = {
                            "Provider Name": {"plaintext": p.name, "copyIcon": true},
                            "Category": {"plaintext": p.category, "cellStyle": {"color": catColor, "fontWeight": "bold"}},
                            "Active": {"plaintext": p.active, "cellStyle": isActive ? {"color": "#2e7d32", "fontWeight": "bold"} : {"color": "#9e9e9e"}},
                            "GUID": {"plaintext": p.guid, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}, "copyIcon": p.guid.length > 0},
                            "Sessions": {"plaintext": sessionStr || "-"},
                            "rowStyle": isDangerous ? {"backgroundColor": "rgba(255,0,0,0.08)"} : isActive ? {"backgroundColor": "rgba(76,175,80,0.06)"} : {},
                        };
                    } else {
                        row = {
                            "Provider Name": {"plaintext": p.name, "copyIcon": true},
                            "GUID": {"plaintext": p.guid, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}, "copyIcon": p.guid.length > 0},
                            "rowStyle": p.security ? {"backgroundColor": "rgba(255,0,0,0.06)"} : {},
                        };
                    }
                    rows.push(row);
                }
                return {"table": [{"headers": headers, "rows": rows, "title": "ETW Providers — " + providers.length + " security-relevant"}]};
            }
        }
        // "query" action: parse key-value session details
        if(combined.includes("ETW Session:") && combined.includes("Buffer Size")){
            let lines = combined.split("\n");
            let headers = [
                {"plaintext": "Property", "type": "string", "width": 180},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.length === 0 || trimmed.match(/^=+$/)) continue;
                let kvMatch = trimmed.match(/^(.+?):\s+(.*)/);
                if(kvMatch){
                    let key = kvMatch[1].trim();
                    let val = kvMatch[2].trim();
                    let valStyle = {};
                    if(key.includes("Security Relevance") && val.length > 0){
                        valStyle = {"color": "#d32f2f", "fontWeight": "bold"};
                    }
                    if(key.includes("Events Lost") && val !== "0"){
                        valStyle = {"color": "#ff8c00", "fontWeight": "bold"};
                    }
                    rows.push({
                        "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                        "Value": {"plaintext": val, "cellStyle": valStyle, "copyIcon": true},
                        "rowStyle": {},
                    });
                }
            }
            if(rows.length > 0){
                let sessionMatch = combined.match(/ETW Session:\s+(\S+)/);
                let title = sessionMatch ? "ETW Session: " + sessionMatch[1] : "ETW Session Details";
                return {"table": [{"headers": headers, "rows": rows, "title": title}]};
            }
        }
        // "patch" / "restore" / "provider-disable" / "provider-enable" actions: status-style output
        if(combined.includes("Patched") || combined.includes("Restored") || combined.includes("kernel trace flag")){
            let lines = combined.split("\n");
            let results = [];
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.length === 0) continue;
                let status = "info";
                if(trimmed.startsWith("[+]") || trimmed.includes("Successfully")) status = "success";
                else if(trimmed.startsWith("[!]")) status = "error";
                else if(trimmed.startsWith("[=]")) status = "neutral";
                results.push({line: trimmed, status: status});
            }
            if(results.length > 0){
                let headers = [
                    {"plaintext": "Status", "type": "string", "width": 80},
                    {"plaintext": "Details", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                let statusColors = {"success": "#2e7d32", "error": "#d32f2f", "neutral": "#9e9e9e", "info": "#1565c0"};
                let statusIcons = {"success": "✓", "error": "✗", "neutral": "=", "info": "ℹ"};
                for(let j = 0; j < results.length; j++){
                    let r = results[j];
                    rows.push({
                        "Status": {"plaintext": statusIcons[r.status] || "•", "cellStyle": {"color": statusColors[r.status], "fontWeight": "bold", "textAlign": "center"}},
                        "Details": {"plaintext": r.line, "cellStyle": {"fontFamily": "monospace"}},
                    });
                }
                let title = combined.includes("Patched") ? "ETW Patch Results" : combined.includes("Restored") ? "ETW Restore Results" : "ETW Provider Update";
                return {"table": [{"headers": headers, "rows": rows, "title": title}]};
            }
        }
        return {"plaintext": combined};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
