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
        let summary = "";
        let inTable = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed.startsWith("Control") && trimmed.includes("Status")){
                inTable = true;
                continue;
            }
            if(trimmed.match(/^-{10,}/)) continue;
            // Summary line: "[*] 8/12 security controls active"
            let sumMatch = trimmed.match(/\[\*\]\s+(\d+\/\d+)\s+security controls active/);
            if(sumMatch){
                summary = sumMatch[1];
                continue;
            }
            if(trimmed === "" || trimmed.startsWith("[*]")) continue;
            if(!inTable) continue;
            // Parse: "[+] Control Name               Status       Details"
            let match = line.match(/^(\[.\])\s+(.{27})\s*(\S+)\s*(.*)/);
            if(match){
                entries.push({
                    indicator: match[1],
                    control: match[2].trim(),
                    status: match[3].trim(),
                    details: match[4].trim()
                });
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Status", "type": "string", "width": 110},
            {"plaintext": "Control", "type": "string", "width": 220},
            {"plaintext": "Details", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        let enabled = 0;
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let rowStyle = {};
            let statusStyle = {};
            let s = e.status.toLowerCase();
            if(s === "enabled"){
                statusStyle = {"color": "#4caf50", "fontWeight": "bold"};
                enabled++;
            } else if(s === "disabled"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                statusStyle = {"color": "#ff8c00"};
            } else if(s === "warning"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                statusStyle = {"color": "#ff8c00", "fontWeight": "bold"};
            } else if(s === "not found" || s === "not"){
                statusStyle = {"color": "#999"};
            }
            rows.push({
                "Status": {"plaintext": e.status, "cellStyle": statusStyle},
                "Control": {"plaintext": e.control},
                "Details": {"plaintext": e.details, "copyIcon": true},
                "rowStyle": rowStyle
            });
        }
        let title = "Security Posture";
        if(summary) title += " (" + summary + " controls active)";
        else title += " (" + enabled + "/" + entries.length + " enabled)";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
