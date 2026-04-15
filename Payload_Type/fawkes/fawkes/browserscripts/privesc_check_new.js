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
        combined = combined.trim();
        // Handle both full check (=== LINUX PRIVILEGE ESCALATION CHECK ===) and single-action output
        let isFullCheck = combined.includes("=== LINUX PRIVILEGE ESCALATION CHECK ===");

        // Split into sections by --- Header ---
        let sections = [];
        if(isFullCheck){
            let parts = combined.split(/---\s+(.+?)\s+---/);
            // parts: [preamble, header1, body1, header2, body2, ...]
            for(let s = 1; s < parts.length; s += 2){
                sections.push({name: parts[s].trim(), body: (parts[s + 1] || "").trim()});
            }
        } else {
            // Single action — treat entire output as one section
            sections.push({name: "Results", body: combined});
        }

        if(sections.length === 0){
            return {"plaintext": combined};
        }

        let tables = [];
        for(let i = 0; i < sections.length; i++){
            let section = sections[i];
            let body = section.body;
            if(!body) continue;

            let lines = body.split("\n");
            let findings = [];
            let interestingItems = [];

            for(let l = 0; l < lines.length; l++){
                let line = lines[l];
                let trimmed = line.trim();
                if(!trimmed) continue;
                // Detect [!] INTERESTING lines
                if(trimmed.startsWith("[!]")){
                    // Header for interesting section — skip, items follow
                    continue;
                }
                // Count/header lines like "SUID binaries (5 found):" or "(none found)"
                if(trimmed.match(/\(\d+ found\):?$/) || trimmed === "(none found)" || trimmed === "(no capabilities found)"){
                    findings.push({text: trimmed, type: "header"});
                    continue;
                }
                // Interesting items flagged by previous sections
                if(lines[l - 1] && lines[l - 1].trim().startsWith("[!]")){
                    interestingItems.push(trimmed);
                    continue;
                }
                // Regular finding line
                findings.push({text: trimmed, type: "item"});
            }

            let headers = [
                {"plaintext": "Finding", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let f = 0; f < findings.length; f++){
                let entry = findings[f];
                let rowStyle = {};
                let cellStyle = {};
                if(entry.type === "header"){
                    cellStyle = {"fontWeight": "bold"};
                }
                // Highlight interesting/dangerous items
                let isInteresting = interestingItems.indexOf(entry.text) >= 0;
                if(isInteresting || entry.text.includes("NOPASSWD") || entry.text.includes("(ALL)")){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                    cellStyle = {"fontWeight": "bold", "color": "#ff8c00"};
                }
                if(entry.text.includes("full sudo access")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.12)"};
                    cellStyle = {"fontWeight": "bold", "color": "#d32f2f"};
                }
                rows.push({
                    "Finding": {"plaintext": entry.text, "cellStyle": cellStyle, "copyIcon": entry.type === "item"},
                    "rowStyle": rowStyle,
                });
            }
            if(rows.length > 0){
                let sectionTitle = section.name;
                let countMatch = body.match(/\((\d+) found\)/);
                if(countMatch){
                    sectionTitle += " (" + countMatch[1] + ")";
                }
                tables.push({"headers": headers, "rows": rows, "title": sectionTitle});
            }
        }
        if(tables.length > 0){
            return {"table": tables};
        }
        return {"plaintext": combined};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
