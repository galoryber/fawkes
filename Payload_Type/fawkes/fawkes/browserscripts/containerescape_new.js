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
        // "check" action: parse escape vectors
        if(combined.includes("CONTAINER ESCAPE VECTOR CHECK")){
            let lines = combined.split("\n");
            let vectors = [];
            let currentVector = null;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                // Vector line: "[!] Description..."
                let vecMatch = trimmed.match(/^\[!\]\s+(.*)/);
                if(vecMatch){
                    if(currentVector) vectors.push(currentVector);
                    currentVector = {description: vecMatch[1], hint: "", details: []};
                    continue;
                }
                // Usage hint: "    Use: container-escape -action ..."
                let hintMatch = trimmed.match(/^Use:\s+(.*)/);
                if(hintMatch && currentVector){
                    currentVector.hint = hintMatch[1];
                    continue;
                }
                // Info line: "[*] Details..."
                let infoMatch = trimmed.match(/^\[\*\]\s+(.*)/);
                if(infoMatch && currentVector){
                    currentVector.details.push(infoMatch[1]);
                    continue;
                }
                // Positive info: "[+] Details..."
                let posMatch = trimmed.match(/^\[\+\]\s+(.*)/);
                if(posMatch && currentVector){
                    currentVector.details.push(posMatch[1]);
                }
            }
            if(currentVector) vectors.push(currentVector);
            if(vectors.length > 0){
                let headers = [
                    {"plaintext": "Escape Vector", "type": "string", "fillWidth": true},
                    {"plaintext": "Command", "type": "string", "width": 350},
                ];
                let rows = [];
                for(let j = 0; j < vectors.length; j++){
                    let v = vectors[j];
                    let desc = v.description;
                    if(v.details.length > 0) desc += " — " + v.details.join("; ");
                    let isPrivileged = desc.toLowerCase().includes("privileged") || desc.toLowerCase().includes("full capabilities");
                    let isSocket = desc.toLowerCase().includes("docker socket");
                    let bg = isPrivileged ? "rgba(255,0,0,0.12)" : (isSocket ? "rgba(255,100,0,0.10)" : "rgba(255,165,0,0.08)");
                    rows.push({
                        "Escape Vector": {"plaintext": desc, "cellStyle": {"fontWeight": "bold"}},
                        "Command": {"plaintext": v.hint, "copyIcon": v.hint.length > 0, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                        "rowStyle": {"backgroundColor": bg},
                    });
                }
                let countMatch = combined.match(/(\d+)\s+escape vector/);
                let count = countMatch ? countMatch[1] : vectors.length;
                return {"table": [{"headers": headers, "rows": rows, "title": "Container Escape Vectors — " + count + " identified"}]};
            }
            // "No obvious escape vectors" case
            if(combined.includes("No obvious escape vectors")){
                return {"plaintext": combined};
            }
        }
        // Execution actions (docker-sock, cgroup, nsenter, mount-host): show output section
        if(combined.includes("--- Output ---")){
            let parts = combined.split("--- Output ---");
            let preamble = parts[0].trim();
            let output = parts.length > 1 ? parts[1].trim() : "";
            let lines = preamble.split("\n");
            let headers = [
                {"plaintext": "Step", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.length === 0) continue;
                let isSuccess = trimmed.startsWith("[+]");
                let isInfo = trimmed.startsWith("[*]");
                let isWarn = trimmed.startsWith("[!]");
                let style = {};
                if(isSuccess) style = {"color": "#4caf50"};
                else if(isWarn) style = {"color": "#ff8c00"};
                else if(isInfo) style = {"color": "#2196f3"};
                rows.push({
                    "Step": {"plaintext": trimmed, "cellStyle": style},
                    "rowStyle": {},
                });
            }
            let tables = [];
            if(rows.length > 0){
                tables.push({"headers": headers, "rows": rows, "title": "Escape Execution"});
            }
            if(output.length > 0){
                // Show the command output as plaintext after the table
                return tables.length > 0
                    ? {"table": tables, "plaintext": "--- Command Output ---\n" + output}
                    : {"plaintext": combined};
            }
            if(tables.length > 0) return {"table": tables};
        }
        return {"plaintext": combined};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
