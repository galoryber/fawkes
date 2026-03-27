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
        let entries = [];
        let currentCategory = "";
        let totalMatch = combined.match(/Total:\s*(\d+)\s*persistence items/);
        let totalCount = totalMatch ? totalMatch[1] : "?";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            // Section headers: --- Category Name ---
            let sectionMatch = trimmed.match(/^---\s+(.+?)\s+---$/);
            if(sectionMatch){
                currentCategory = sectionMatch[1];
                continue;
            }
            // Skip header/footer/empty/separator
            if(trimmed === "" || trimmed.startsWith("===") || trimmed.startsWith("---")) continue;
            if(trimmed === "(none found)") continue;
            if(!currentCategory) continue;
            entries.push({category: currentCategory, detail: trimmed});
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Category", "type": "string", "width": 200},
            {"plaintext": "Detail", "type": "string", "fillWidth": true},
        ];
        let categoryColors = {
            "Registry Run Keys": "rgba(255,165,0,0.12)",
            "Startup Folders": "rgba(255,165,0,0.12)",
            "Winlogon": "rgba(255,0,0,0.1)",
            "Image File Execution Options (Debugger)": "rgba(255,0,0,0.15)",
            "AppInit_DLLs": "rgba(255,0,0,0.15)",
            "Scheduled Tasks": "rgba(0,150,255,0.1)",
            "Non-Microsoft Services": "rgba(0,150,255,0.1)",
        };
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let bgColor = categoryColors[e.category] || "rgba(128,128,128,0.05)";
            rows.push({
                "Category": {"plaintext": e.category},
                "Detail": {"plaintext": e.detail, "copyIcon": true},
                "rowStyle": {"backgroundColor": bgColor},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Persistence Enumeration \u2014 " + totalCount + " items found",
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
