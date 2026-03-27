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
        let records = [];
        let title = "DNS Results";
        let currentType = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            // Extract title from first [*] line
            if(trimmed.startsWith("[*]")){
                title = trimmed.replace("[*]", "").trim();
                continue;
            }
            // Section headers like [A/AAAA], [MX], [SRV _ldap._tcp], etc.
            let sectionMatch = trimmed.match(/^\[([A-Z\/]+(?:\s+\S+)?)\]/);
            if(sectionMatch){
                currentType = sectionMatch[1];
                continue;
            }
            // Skip separator lines
            if(trimmed.match(/^={10,}$/) || trimmed.match(/^-{10,}$/)){
                continue;
            }
            // Zone transfer format: name  type  data  TTL=N
            let zoneMatch = trimmed.match(/^(\S+)\s+(A|AAAA|MX|NS|SRV|TXT|CNAME|SOA|PTR)\s+(.+?)(?:\s+TTL=(\d+))?$/);
            if(zoneMatch){
                records.push({type: zoneMatch[2], name: zoneMatch[1], value: zoneMatch[3].trim(), ttl: zoneMatch[4] || ""});
                continue;
            }
            // DC discovery: host:port -> IP
            let dcMatch = trimmed.match(/^(\S+):(\d+)\s*\u2192\s*(.+)$/);
            if(!dcMatch){
                dcMatch = trimmed.match(/^(\S+):(\d+)\s*->\s*(.+)$/);
            }
            if(dcMatch){
                records.push({type: currentType || "SRV", name: dcMatch[1], value: dcMatch[3], port: dcMatch[2]});
                continue;
            }
            // SRV format: hostname:port (priority=N, weight=N)
            let srvMatch = trimmed.match(/^(\S+):(\d+)\s*\(priority=(\d+),\s*weight=(\d+)\)$/);
            if(srvMatch){
                records.push({type: "SRV", name: srvMatch[1], value: "port=" + srvMatch[2], priority: srvMatch[3], weight: srvMatch[4]});
                continue;
            }
            // MX format: hostname (preference=N)
            let mxMatch = trimmed.match(/^(\S+)\s*\(preference=(\d+)\)$/);
            if(mxMatch){
                records.push({type: "MX", name: mxMatch[1], value: "pref=" + mxMatch[2]});
                continue;
            }
            // Simple record (IP address, hostname, TXT string)
            if(trimmed.length > 0 && !trimmed.startsWith("[") && !trimmed.startsWith("(") && !trimmed.startsWith("Total") && !trimmed.startsWith("Crack")){
                // Indented result line
                if(line.match(/^\s{2,}/) && trimmed.length > 0){
                    let rType = currentType || "A";
                    records.push({type: rType, name: "", value: trimmed});
                }
            }
        }
        if(records.length === 0){
            return {"plaintext": combined};
        }
        let typeColors = {
            "A": "rgba(0,150,255,0.08)",
            "AAAA": "rgba(0,150,255,0.08)",
            "MX": "rgba(0,200,0,0.08)",
            "NS": "rgba(128,0,255,0.08)",
            "SRV": "rgba(255,165,0,0.08)",
            "TXT": "rgba(128,128,128,0.08)",
            "CNAME": "rgba(0,200,200,0.08)",
        };
        let headers = [
            {"plaintext": "Type", "type": "string", "width": 80},
            {"plaintext": "Name", "type": "string", "width": 250},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < records.length; j++){
            let r = records[j];
            let bg = typeColors[r.type] || "transparent";
            rows.push({
                "Type": {"plaintext": r.type, "cellStyle": {"fontWeight": "bold"}},
                "Name": {"plaintext": r.name, "copyIcon": r.name.length > 0},
                "Value": {"plaintext": r.value, "copyIcon": true},
                "rowStyle": {"backgroundColor": bg},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title + " \u2014 " + records.length + " records",
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
