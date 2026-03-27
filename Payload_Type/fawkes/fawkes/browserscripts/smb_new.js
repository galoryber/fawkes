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
        // Detect mode: shares listing vs directory listing
        let isDir = combined.includes("Size") && combined.includes("Modified") && combined.includes("Name");
        let isShares = combined.includes("Shares on");
        if(isDir){
            // Parse directory listing
            let entries = [];
            let title = "";
            let pastHeader = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.startsWith("[*]")){
                    title = trimmed.replace("[*]", "").trim();
                    continue;
                }
                if(trimmed.match(/^-{10,}$/)){
                    pastHeader = true;
                    continue;
                }
                if(!pastHeader || trimmed.length === 0) continue;
                // Parse: Size  Modified  Name
                let m = trimmed.match(/^(\S+(?:\s+\S+)?)\s{2,}(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s{2,}(.+)$/);
                if(m){
                    let size = m[1];
                    let modified = m[2];
                    let name = m[3];
                    let isDirectory = size === "<DIR>" || name.endsWith("/");
                    entries.push({size: size, modified: modified, name: name, isDirectory: isDirectory});
                }
            }
            if(entries.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Name", "type": "string", "fillWidth": true},
                {"plaintext": "Size", "type": "string", "width": 100},
                {"plaintext": "Modified", "type": "string", "width": 170},
            ];
            let rows = [];
            for(let j = 0; j < entries.length; j++){
                let e = entries[j];
                let bg = e.isDirectory ? "rgba(0,150,255,0.06)" : "transparent";
                rows.push({
                    "Name": {"plaintext": e.name, "copyIcon": true, "cellStyle": e.isDirectory ? {"fontWeight": "bold"} : {}},
                    "Size": {"plaintext": e.size, "cellStyle": e.isDirectory ? {"color": "#888"} : {}},
                    "Modified": {"plaintext": e.modified},
                    "rowStyle": {"backgroundColor": bg},
                });
            }
            return {"table": [{"headers": headers, "rows": rows, "title": title || "SMB Directory \u2014 " + entries.length + " entries"}]};
        }
        if(isShares){
            // Parse shares listing
            let shares = [];
            let title = "";
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.startsWith("[*]")){
                    title = trimmed.replace("[*]", "").trim();
                    continue;
                }
                if(trimmed.match(/^-{5,}$/) || trimmed.length === 0) continue;
                // UNC path: \\SERVER\ShareName
                if(trimmed.startsWith("\\\\")){
                    let parts = trimmed.replace(/^\\\\/, "").split("\\");
                    let server = parts[0] || "";
                    let share = parts.slice(1).join("\\");
                    let isAdmin = share.endsWith("$");
                    shares.push({path: trimmed, server: server, share: share, isAdmin: isAdmin});
                }
            }
            if(shares.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Share", "type": "string", "width": 200},
                {"plaintext": "UNC Path", "type": "string", "fillWidth": true},
                {"plaintext": "Type", "type": "string", "width": 80},
            ];
            let rows = [];
            for(let j = 0; j < shares.length; j++){
                let s = shares[j];
                let bg = s.isAdmin ? "rgba(255,165,0,0.1)" : "transparent";
                rows.push({
                    "Share": {"plaintext": s.share, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                    "UNC Path": {"plaintext": s.path, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                    "Type": {"plaintext": s.isAdmin ? "Admin$" : "User"},
                    "rowStyle": {"backgroundColor": bg},
                });
            }
            return {"table": [{"headers": headers, "rows": rows, "title": title || "SMB Shares \u2014 " + shares.length}]};
        }
        // Fallback: plaintext
        return {"plaintext": combined};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
