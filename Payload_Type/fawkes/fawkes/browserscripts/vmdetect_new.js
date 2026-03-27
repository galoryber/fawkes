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
        let hypervisor = "";
        let inTable = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            // Extract hypervisor line
            let hvMatch = trimmed.match(/Hypervisor:\s+(.+)/);
            if(hvMatch){
                hypervisor = hvMatch[1];
                continue;
            }
            // Skip header and separator lines
            if(trimmed.startsWith("Check") && trimmed.includes("Result")){
                inTable = true;
                continue;
            }
            if(trimmed.match(/^-{10,}/)){
                continue;
            }
            if(trimmed === "" || trimmed.startsWith("[*]")) continue;
            if(!inTable) continue;
            // Parse table rows: "Check                              Result       Details"
            let match = line.match(/^(.{35})\s*(\S+)\s+(.*)/);
            if(match){
                entries.push({
                    check: match[1].trim(),
                    result: match[2].trim(),
                    details: match[3].trim()
                });
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Result", "type": "string", "width": 100},
            {"plaintext": "Check", "type": "string", "width": 250},
            {"plaintext": "Details", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        let vmCount = 0;
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let rowStyle = {};
            let resultStyle = {};
            let r = e.result.toLowerCase();
            if(r === "vm"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                resultStyle = {"color": "#ff8c00", "fontWeight": "bold"};
                vmCount++;
            } else if(r === "cloud"){
                rowStyle = {"backgroundColor": "rgba(0,150,255,0.08)"};
                resultStyle = {"color": "#0096ff", "fontWeight": "bold"};
            } else if(r === "error"){
                resultStyle = {"color": "#999"};
            }
            rows.push({
                "Result": {"plaintext": e.result, "cellStyle": resultStyle},
                "Check": {"plaintext": e.check},
                "Details": {"plaintext": e.details, "copyIcon": true},
                "rowStyle": rowStyle
            });
        }
        let title = "VM Detection (" + entries.length + " checks";
        if(hypervisor) title += ", Hypervisor: " + hypervisor;
        if(vmCount > 0) title += ", " + vmCount + " VM indicators";
        title += ")";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
