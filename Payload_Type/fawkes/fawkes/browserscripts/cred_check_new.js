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
        if(!combined.includes("=== CREDENTIAL CHECK ===")){
            return {"plaintext": combined};
        }
        // Parse user line
        let userMatch = combined.match(/User:\s+(.+)/);
        let user = userMatch ? userMatch[1].trim() : "unknown";

        // Parse summary line
        let summaryMatch = combined.match(/---\s*(\d+)\s*host\(s\)\s*checked,\s*(\d+)\s*successful/);
        let totalHosts = summaryMatch ? summaryMatch[1] : "?";
        let totalSuccess = summaryMatch ? summaryMatch[2] : "?";

        // Parse host sections: --- hostname ---
        let hostSections = combined.split(/---\s+([^\s]+?)\s+---/);
        // hostSections: [preamble, host1, body1, host2, body2, ..., summaryHost, summaryBody]

        let headers = [
            {"plaintext": "Host", "type": "string", "fillWidth": true},
            {"plaintext": "Protocol", "type": "string", "width": 120},
            {"plaintext": "Status", "type": "string", "width": 80},
            {"plaintext": "Detail", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let successCount = 0;

        for(let s = 1; s < hostSections.length; s += 2){
            let host = hostSections[s].trim();
            let body = hostSections[s + 1] || "";
            // Skip summary line (contains "host(s) checked")
            if(host.match(/^\d+$/) || body.includes("host(s) checked")){
                continue;
            }
            let lines = body.split("\n");
            for(let l = 0; l < lines.length; l++){
                let line = lines[l].trim();
                if(!line) continue;
                // Parse: [+] PROTOCOL  Detail  or  [-] PROTOCOL  Detail
                let m = line.match(/^\[([+-])\]\s+(\S+)\s+(.*)/);
                if(!m) continue;
                let success = m[1] === "+";
                let protocol = m[2];
                let detail = m[3].trim();
                let rowStyle = {};
                let statusText = "FAIL";
                let statusStyle = {};
                if(success){
                    rowStyle = {"backgroundColor": "rgba(76,175,80,0.15)"};
                    statusText = "OK";
                    statusStyle = {"fontWeight": "bold", "color": "#4caf50"};
                    successCount++;
                }
                rows.push({
                    "Host": {"plaintext": host, "copyIcon": true},
                    "Protocol": {"plaintext": protocol},
                    "Status": {"plaintext": statusText, "cellStyle": statusStyle},
                    "Detail": {"plaintext": detail},
                    "rowStyle": rowStyle,
                });
            }
        }

        let title = "Credential Check: " + user + " (" + totalHosts + " hosts, " + totalSuccess + " success)";
        if(rows.length > 0){
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
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
