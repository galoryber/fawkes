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
        // Install/remove results — show as plaintext
        if(combined.startsWith("Systemd service installed") || combined.startsWith("Removed:")){
            return {"plaintext": combined};
        }
        let lines = combined.split("\n");
        let entries = [];
        let currentScope = "";
        let currentEntry = null;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^={10,}/)) continue;
            // Scope headers: "User Services (...)" or "System Services (...)"
            if(trimmed.startsWith("User Services")){
                currentScope = "User";
                continue;
            }
            if(trimmed.startsWith("System Services")){
                currentScope = "System";
                continue;
            }
            if(trimmed === "(none)") continue;
            // Entry: "[1] myservice.service"
            let entryMatch = trimmed.match(/^\[(\d+)\]\s+(.*)/);
            if(entryMatch){
                if(currentEntry) entries.push(currentEntry);
                currentEntry = {scope: currentScope, name: entryMatch[2], description: "", execStart: "", onCalendar: ""};
                continue;
            }
            if(currentEntry){
                let descMatch = trimmed.match(/^Description:\s+(.*)/);
                if(descMatch) currentEntry.description = descMatch[1];
                let execMatch = trimmed.match(/^ExecStart:\s+(.*)/);
                if(execMatch) currentEntry.execStart = execMatch[1];
                let calMatch = trimmed.match(/^OnCalendar:\s+(.*)/);
                if(calMatch) currentEntry.onCalendar = calMatch[1];
            }
        }
        if(currentEntry) entries.push(currentEntry);
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Scope", "type": "string", "width": 80},
            {"plaintext": "Service", "type": "string", "width": 200},
            {"plaintext": "Description", "type": "string", "width": 200},
            {"plaintext": "ExecStart / Timer", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let isTimer = e.name.endsWith(".timer");
            let execOrTimer = isTimer ? e.onCalendar : e.execStart;
            let scopeStyle = e.scope === "System" ? {"fontWeight": "bold", "color": "#d94f00"} : {};
            rows.push({
                "Scope": {"plaintext": e.scope, "cellStyle": scopeStyle},
                "Service": {"plaintext": e.name, "cellStyle": {"fontWeight": "bold"}, "copyIcon": true},
                "Description": {"plaintext": e.description},
                "ExecStart / Timer": {"plaintext": execOrTimer, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Systemd Persistence \u2014 " + entries.length + " services"}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
