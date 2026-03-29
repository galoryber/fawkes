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
        if(combined.startsWith("Installed LaunchAgent") || combined.startsWith("Removed LaunchAgent")){
            return {"plaintext": combined};
        }
        let lines = combined.split("\n");
        let entries = [];
        let currentCategory = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.startsWith("=== ")) continue;
            // Category headers: "--- User LaunchAgents: /path ---"
            let catMatch = trimmed.match(/^---\s+(.+?):\s+(.+?)\s+---/);
            if(catMatch){
                currentCategory = catMatch[1];
                continue;
            }
            if(trimmed === "(empty)") continue;
            // Entry: "  com.apple.label (1024 bytes)"
            let entryMatch = trimmed.match(/^(\S+)\s+\((\d+)\s+bytes?\)/);
            if(entryMatch && currentCategory){
                entries.push({category: currentCategory, label: entryMatch[1], size: parseInt(entryMatch[2])});
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Category", "type": "string", "width": 180},
            {"plaintext": "Label", "type": "string", "fillWidth": true},
            {"plaintext": "Size", "type": "string", "width": 100}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let isDaemon = e.category.includes("Daemon");
            let catStyle = isDaemon ? {"fontWeight": "bold", "color": "#d94f00"} : {};
            let sizeStr = e.size >= 1024 ? (e.size / 1024).toFixed(1) + " KB" : e.size + " B";
            rows.push({
                "Category": {"plaintext": e.category, "cellStyle": catStyle},
                "Label": {"plaintext": e.label, "cellStyle": {"fontWeight": "bold"}, "copyIcon": true},
                "Size": {"plaintext": sizeStr}
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "macOS Persistence \u2014 " + entries.length + " agents/daemons"}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
