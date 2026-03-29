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
        let interestingCount = 0;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            // Section headers with counts: e.g. "SUID binaries (3 found):" or "--- Section ---"
            let sectionMatch = trimmed.match(/^---\s+(.+?)\s+---$/);
            if(sectionMatch){
                currentCategory = sectionMatch[1];
                continue;
            }
            // Also match section-style headers without dashes
            let headerMatch = trimmed.match(/^([A-Z][A-Za-z /]+)\s*\(\d+\s*found\):/);
            if(headerMatch){
                currentCategory = headerMatch[1].trim();
                continue;
            }
            // Skip header/footer/empty/separator
            if(trimmed === "" || trimmed.startsWith("===") || trimmed.startsWith("---")) continue;
            if(trimmed === "(none found)" || trimmed === "(none)") continue;
            if(!currentCategory) continue;
            let isInteresting = trimmed.startsWith("[!]");
            if(isInteresting) interestingCount++;
            let detail = isInteresting ? trimmed.substring(4).trim() : trimmed;
            entries.push({
                category: currentCategory,
                detail: detail,
                interesting: isInteresting,
            });
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Category", "type": "string", "width": 220},
            {"plaintext": "Finding", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let rowStyle = {};
            if(e.interesting){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.12)"};
            } else if(e.category.toLowerCase().includes("interesting")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
            }
            rows.push({
                "Category": {"plaintext": e.category},
                "Finding": {
                    "plaintext": e.detail,
                    "copyIcon": true,
                    "cellStyle": e.interesting ? {"fontWeight": "bold"} : {},
                },
                "rowStyle": rowStyle,
            });
        }
        let title = "Privilege Escalation Check \u2014 " + entries.length + " findings";
        if(interestingCount > 0){
            title += " (" + interestingCount + " interesting)";
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
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
