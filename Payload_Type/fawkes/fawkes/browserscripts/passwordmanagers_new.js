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
        if(combined.includes("No password manager")){
            return {"plaintext": combined};
        }
        let lines = combined.split("\n");
        let items = [];
        let currentManager = "";
        let currentPath = "";
        let currentSize = "";
        let currentDate = "";
        let currentDetails = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            // Manager+path line: "[ManagerName] /path/to/file"
            let mgMatch = trimmed.match(/^\[(.+?)\]\s+(.*)/);
            if(mgMatch){
                if(currentManager){
                    items.push({manager: currentManager, path: currentPath, size: currentSize, date: currentDate, details: currentDetails});
                }
                currentManager = mgMatch[1];
                currentPath = mgMatch[2];
                currentSize = "";
                currentDate = "";
                currentDetails = "";
                continue;
            }
            // Size+date line: "  Size: 4.2KB, Modified: 2026-01-15T..."
            let sizeMatch = trimmed.match(/^Size:\s*([^,]+),\s*Modified:\s*(.*)/);
            if(sizeMatch){
                currentSize = sizeMatch[1].trim();
                currentDate = sizeMatch[2].trim();
                continue;
            }
            // Details line (indented, not empty)
            if(trimmed.length > 0 && line.startsWith("  ") && !trimmed.startsWith("===") && !trimmed.startsWith("Size:")){
                currentDetails = trimmed;
            }
        }
        if(currentManager){
            items.push({manager: currentManager, path: currentPath, size: currentSize, date: currentDate, details: currentDetails});
        }
        if(items.length === 0){
            return {"plaintext": combined};
        }
        let managerColors = {
            "KeePass": "rgba(76,175,80,0.10)",
            "1Password": "rgba(33,150,243,0.10)",
            "Bitwarden": "rgba(33,150,243,0.10)",
            "LastPass": "rgba(255,0,0,0.10)",
            "Chrome": "rgba(255,165,0,0.10)",
            "Firefox": "rgba(255,140,0,0.10)",
            "Edge": "rgba(0,120,215,0.10)",
        };
        let headers = [
            {"plaintext": "Manager", "type": "string", "width": 120},
            {"plaintext": "Path", "type": "string", "fillWidth": true},
            {"plaintext": "Size", "type": "string", "width": 80},
            {"plaintext": "Modified", "type": "string", "width": 150},
            {"plaintext": "Details", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < items.length; j++){
            let it = items[j];
            let bg = "";
            for(let key in managerColors){
                if(it.manager.includes(key)){ bg = managerColors[key]; break; }
            }
            rows.push({
                "Manager": {"plaintext": it.manager, "cellStyle": {"fontWeight": "bold"}},
                "Path": {"plaintext": it.path, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Size": {"plaintext": it.size},
                "Modified": {"plaintext": it.date},
                "Details": {"plaintext": it.details},
                "rowStyle": bg ? {"backgroundColor": bg} : {},
            });
        }
        // Group summary
        let mgrs = {};
        for(let it of items){ mgrs[it.manager] = (mgrs[it.manager]||0) + 1; }
        let mgrSummary = Object.entries(mgrs).map(function(e){ return e[1] + " " + e[0]; }).join(", ");
        return {"table": [{"headers": headers, "rows": rows, "title": "Password Managers — " + items.length + " items (" + mgrSummary + ")"}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
