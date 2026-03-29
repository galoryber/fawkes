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
        let rules = [];
        let title = "";
        let pastHeader = false;
        for(let i = 0; i < lines.length; i++){
            let trimmed = lines[i].trim();
            if(trimmed.includes("Firewall Rules") || trimmed.includes("firewall rules")){
                title = trimmed;
                continue;
            }
            if(trimmed.match(/^-{10,}$/)){
                pastHeader = true;
                continue;
            }
            if(trimmed.startsWith("Showing ")){
                title = (title ? title + " \u2014 " : "") + trimmed;
                continue;
            }
            if(!pastHeader || trimmed.length === 0) continue;
            // Skip the header row
            if(trimmed.startsWith("Name") && trimmed.includes("Dir") && trimmed.includes("Action")){
                continue;
            }
            // Parse fixed-width columns or multi-space delimited
            let parts = trimmed.split(/\s{2,}/);
            if(parts.length >= 4){
                let name = parts[0].trim();
                let dir = parts[1].trim();
                let action = parts[2].trim();
                let proto = parts.length >= 4 ? parts[3].trim() : "";
                let enabled = parts.length >= 5 ? parts[4].trim() : "";
                let ports = parts.length >= 6 ? parts[5].trim() : "";
                let program = parts.length >= 7 ? parts[6].trim() : "";
                rules.push({name: name, direction: dir, action: action, protocol: proto, enabled: enabled, ports: ports, program: program});
            }
        }
        if(rules.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Name", "type": "string", "fillWidth": true},
            {"plaintext": "Dir", "type": "string", "width": 50},
            {"plaintext": "Action", "type": "string", "width": 65},
            {"plaintext": "Proto", "type": "string", "width": 55},
            {"plaintext": "Ports", "type": "string", "width": 120},
            {"plaintext": "Program", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < rules.length; j++){
            let r = rules[j];
            let isBlock = r.action.toLowerCase() === "block";
            let isInbound = r.direction.toLowerCase() === "in";
            let bg = isBlock ? "rgba(255,0,0,0.08)" : (isInbound ? "rgba(0,150,255,0.06)" : "transparent");
            rows.push({
                "Name": {"plaintext": r.name, "cellStyle": {"fontWeight": "bold"}},
                "Dir": {"plaintext": r.direction, "cellStyle": isInbound ? {"color": "#0066cc"} : {"color": "#888"}},
                "Action": {"plaintext": r.action, "cellStyle": isBlock ? {"color": "red", "fontWeight": "bold"} : {"color": "green"}},
                "Proto": {"plaintext": r.protocol},
                "Ports": {"plaintext": r.ports, "copyIcon": r.ports !== "*" && r.ports.length > 0},
                "Program": {"plaintext": r.program, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}},
                "rowStyle": {"backgroundColor": bg},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title || "Firewall Rules \u2014 " + rules.length + " rules",
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
