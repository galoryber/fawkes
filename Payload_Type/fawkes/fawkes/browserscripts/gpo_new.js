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
        let lines = combined.split("\n");
        let tables = [];
        // Parse GPO list entries
        let gpoEntries = [];
        let linkEntries = [];
        let findEntries = [];
        let currentGPO = "";
        let currentGUID = "";
        let currentSection = "";
        let findCategory = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^={10,}/) || trimmed.match(/^-{10,}/)) continue;
            // Section headers
            let secMatch = trimmed.match(/^\[\*\]\s+Group Policy Objects\s+\((\d+)/);
            if(secMatch){ currentSection = "list"; continue; }
            let linkMatch = trimmed.match(/^\[\*\]\s+GPO Links/);
            if(linkMatch){ currentSection = "links"; continue; }
            let findMatch = trimmed.match(/^\[\*\]\s+Interesting GPO Settings/);
            if(findMatch){ currentSection = "find"; continue; }
            // GPO entry
            let gpoMatch = trimmed.match(/^\[GPO\]\s+(.*)/);
            if(gpoMatch){
                currentGPO = gpoMatch[1];
                // For links section, GPO name may include GUID
                let nameGuid = currentGPO.match(/^(.+?)\s+(\{[^}]+\})/);
                if(nameGuid){
                    currentGPO = nameGuid[1];
                    currentGUID = nameGuid[2];
                }
                continue;
            }
            if(currentSection === "list"){
                let kvMatch = trimmed.match(/^(\w[\w\s]*?):\s+(.*)/);
                if(kvMatch){
                    let key = kvMatch[1].trim();
                    let val = kvMatch[2].trim();
                    // Find or create entry for current GPO
                    let entry = gpoEntries.find(e => e.name === currentGPO);
                    if(!entry){
                        entry = {name: currentGPO};
                        gpoEntries.push(entry);
                    }
                    if(key === "GUID") entry.guid = val;
                    else if(key === "SYSVOL") entry.sysvol = val;
                    else if(key === "Version") entry.version = val;
                    else if(key === "Status") entry.status = val;
                    else if(key === "Created") entry.created = val;
                    else if(key === "Modified") entry.modified = val;
                }
            }
            if(currentSection === "links"){
                let arrowMatch = trimmed.match(/^\u2192\s+(.*)/);
                if(arrowMatch){
                    let linkTarget = arrowMatch[1];
                    let enforced = linkTarget.includes("[ENFORCED]");
                    let disabled = linkTarget.includes("[DISABLED]");
                    linkTarget = linkTarget.replace(/\s*\[ENFORCED\]/g, "").replace(/\s*\[DISABLED\]/g, "").trim();
                    linkEntries.push({gpo: currentGPO, guid: currentGUID, target: linkTarget, enforced: enforced, disabled: disabled});
                }
            }
            if(currentSection === "find"){
                let catMatch = trimmed.match(/^\[(.+)\]$/);
                if(catMatch){
                    findCategory = catMatch[1];
                    continue;
                }
                // GPO name under category
                if(trimmed && !trimmed.startsWith("GUID:") && !trimmed.startsWith("CSE:") && findCategory){
                    currentGPO = trimmed;
                }
                let cseMatch = trimmed.match(/^CSE:\s+(.*)/);
                if(cseMatch){
                    findEntries.push({category: findCategory, gpo: currentGPO, cse: cseMatch[1]});
                }
            }
        }
        // Build tables
        if(gpoEntries.length > 0){
            let headers = [
                {"plaintext": "GPO Name", "type": "string", "width": 200},
                {"plaintext": "Status", "type": "string", "width": 120},
                {"plaintext": "Version", "type": "string", "width": 150},
                {"plaintext": "Modified", "type": "string", "width": 170},
                {"plaintext": "GUID", "type": "string", "width": 280}
            ];
            let rows = [];
            for(let j = 0; j < gpoEntries.length; j++){
                let e = gpoEntries[j];
                let statusStyle = {};
                let rowStyle = {};
                if(e.status && e.status.includes("Disabled")){
                    statusStyle = {"color": "#999"};
                    rowStyle = {"backgroundColor": "rgba(0,0,0,0.05)"};
                } else {
                    statusStyle = {"color": "#4caf50"};
                }
                rows.push({
                    "GPO Name": {"plaintext": e.name || "", "cellStyle": {"fontWeight": "bold"}},
                    "Status": {"plaintext": e.status || "", "cellStyle": statusStyle},
                    "Version": {"plaintext": e.version || ""},
                    "Modified": {"plaintext": e.modified || ""},
                    "GUID": {"plaintext": e.guid || "", "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                    "rowStyle": rowStyle
                });
            }
            tables.push({"headers": headers, "rows": rows, "title": "Group Policy Objects \u2014 " + gpoEntries.length + " GPOs"});
        }
        if(linkEntries.length > 0){
            let headers = [
                {"plaintext": "GPO", "type": "string", "width": 200},
                {"plaintext": "Linked To", "type": "string", "fillWidth": true},
                {"plaintext": "Enforced", "type": "string", "width": 90},
                {"plaintext": "Disabled", "type": "string", "width": 90}
            ];
            let rows = [];
            for(let j = 0; j < linkEntries.length; j++){
                let e = linkEntries[j];
                let rowStyle = {};
                if(e.enforced) rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                if(e.disabled) rowStyle = {"backgroundColor": "rgba(0,0,0,0.05)"};
                rows.push({
                    "GPO": {"plaintext": e.gpo, "cellStyle": {"fontWeight": "bold"}},
                    "Linked To": {"plaintext": e.target, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                    "Enforced": {"plaintext": e.enforced ? "Yes" : "", "cellStyle": e.enforced ? {"color": "#ff8c00", "fontWeight": "bold"} : {}},
                    "Disabled": {"plaintext": e.disabled ? "Yes" : "", "cellStyle": e.disabled ? {"color": "#999"} : {}},
                    "rowStyle": rowStyle
                });
            }
            tables.push({"headers": headers, "rows": rows, "title": "GPO Links \u2014 " + linkEntries.length + " links"});
        }
        if(findEntries.length > 0){
            let headers = [
                {"plaintext": "Category", "type": "string", "width": 200},
                {"plaintext": "GPO", "type": "string", "width": 200},
                {"plaintext": "CSE", "type": "string", "fillWidth": true}
            ];
            let rows = [];
            for(let j = 0; j < findEntries.length; j++){
                let e = findEntries[j];
                rows.push({
                    "Category": {"plaintext": e.category, "cellStyle": {"fontWeight": "bold"}},
                    "GPO": {"plaintext": e.gpo},
                    "CSE": {"plaintext": e.cse},
                    "rowStyle": {"backgroundColor": "rgba(255,165,0,0.08)"}
                });
            }
            tables.push({"headers": headers, "rows": rows, "title": "Interesting GPO Settings \u2014 " + findEntries.length + " findings"});
        }
        if(tables.length === 0){
            return {"plaintext": combined};
        }
        return {"table": tables};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
