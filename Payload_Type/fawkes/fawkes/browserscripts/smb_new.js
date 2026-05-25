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
        if(combined.includes("=== Share Sweep Chain Complete")){
            return renderChainTable(combined, "Share Sweep Chain");
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
        // Detect JSON results (ls, taint)
        try {
            let parsed = JSON.parse(combined);
            if(parsed.action === "ls" && parsed.files){
                let headers = [
                    {"plaintext": "Name", "type": "string", "fillWidth": true},
                    {"plaintext": "Size", "type": "string", "width": 100},
                    {"plaintext": "Modified", "type": "string", "width": 170},
                ];
                let rows = [];
                for(let j = 0; j < parsed.files.length; j++){
                    let f = parsed.files[j];
                    let isDirectory = !f.is_file;
                    let sizeStr = isDirectory ? "<DIR>" : formatBytes(f.size);
                    let modStr = f.modify_time ? f.modify_time.replace("T", " ").replace(/Z$/, "").replace(/\+.*/, "") : "";
                    let displayName = f.name + (isDirectory ? "/" : "");
                    let bg = isDirectory ? "rgba(0,150,255,0.06)" : "transparent";
                    rows.push({
                        "Name": {"plaintext": displayName, "copyIcon": true, "cellStyle": isDirectory ? {"fontWeight": "bold"} : {}},
                        "Size": {"plaintext": sizeStr, "cellStyle": isDirectory ? {"color": "#888"} : {}},
                        "Modified": {"plaintext": modStr},
                        "rowStyle": {"backgroundColor": bg},
                    });
                }
                let title = "\\\\" + (parsed.host || "") + "\\" + (parsed.share || "") + "\\" + (parsed.name || "") + " — " + parsed.files.length + " entries";
                return {"table": [{"headers": headers, "rows": rows, "title": title}]};
            }
            if(parsed.action === "taint"){
                let tables = [];
                // Planted files table
                if(parsed.planted && parsed.planted.length > 0){
                    let pHeaders = [
                        {"plaintext": "Share", "type": "string", "width": 150},
                        {"plaintext": "Path", "type": "string", "fillWidth": true},
                        {"plaintext": "Size", "type": "string", "width": 80},
                        {"plaintext": "Timestomped", "type": "string", "width": 110},
                        {"plaintext": "Stomp Source", "type": "string", "width": 200},
                    ];
                    let pRows = [];
                    for(let j = 0; j < parsed.planted.length; j++){
                        let p = parsed.planted[j];
                        pRows.push({
                            "Share": {"plaintext": p.share, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                            "Path": {"plaintext": p.path, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                            "Size": {"plaintext": p.size + " B"},
                            "Timestomped": {"plaintext": p.timestomped ? "\u2705 Yes" : "\u274c No",
                                "cellStyle": {"color": p.timestomped ? "#4caf50" : "#f44336"}},
                            "Stomp Source": {"plaintext": p.stomp_source || "\u2014"},
                            "rowStyle": {"backgroundColor": "rgba(76,175,80,0.08)"},
                        });
                    }
                    tables.push({"headers": pHeaders, "rows": pRows,
                        "title": "\ud83d\udea9 Taint: " + parsed.planted.length + " file(s) planted on \\\\" + parsed.host});
                }
                // Skipped shares table
                if(parsed.skipped && parsed.skipped.length > 0){
                    let sHeaders = [
                        {"plaintext": "Share", "type": "string", "width": 150},
                        {"plaintext": "Reason", "type": "string", "fillWidth": true},
                    ];
                    let sRows = [];
                    for(let k = 0; k < parsed.skipped.length; k++){
                        let s = parsed.skipped[k];
                        sRows.push({
                            "Share": {"plaintext": s.share},
                            "Reason": {"plaintext": s.reason, "cellStyle": {"color": "#888"}},
                        });
                    }
                    tables.push({"headers": sHeaders, "rows": sRows,
                        "title": "Skipped Shares (" + parsed.skipped.length + ")"});
                }
                if(tables.length > 0){
                    return {"table": tables};
                }
                return {"plaintext": "Taint complete on " + parsed.host + ": " + parsed.shares_tested + " shares tested, 0 planted."};
            }
        } catch(e) { /* not JSON, fall through */ }
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

function renderChainTable(text, chainName){
    let lines = text.split("\n");
    let headers = [
        {"plaintext": "Status", "type": "string", "width": 100},
        {"plaintext": "Command", "type": "string", "width": 200},
        {"plaintext": "Detail", "type": "string", "fillWidth": true},
    ];
    let rows = [];
    let successCount = 0;
    let errorCount = 0;
    for(let i = 0; i < lines.length; i++){
        let line = lines[i].trim();
        if(!line || line.match(/^={3,}$/)) continue;
        let stepMatch = line.match(/^\[Step (\d+\/\d+)\]\s+(.*)/);
        if(stepMatch){
            rows.push({
                "Status": {"plaintext": stepMatch[1], "cellStyle": {"fontWeight": "bold", "color": "#2196f3"}},
                "Command": {"plaintext": "Progress"},
                "Detail": {"plaintext": stepMatch[2]},
                "rowStyle": {"backgroundColor": "rgba(33,150,243,0.08)"},
            });
            continue;
        }
        let taskMatch = line.match(/^\[(success|error|unknown)\]\s+(\S+)\s+(.*)/);
        if(taskMatch){
            let status = taskMatch[1].toUpperCase();
            let isSuccess = status === "SUCCESS";
            if(isSuccess) successCount++;
            else if(status === "ERROR") errorCount++;
            rows.push({
                "Status": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": isSuccess ? "#4caf50" : (status === "ERROR" ? "#f44336" : "#9e9e9e")}},
                "Command": {"plaintext": taskMatch[2]},
                "Detail": {"plaintext": taskMatch[3]},
                "rowStyle": {"backgroundColor": isSuccess ? "rgba(76,175,80,0.08)" : (status === "ERROR" ? "rgba(244,67,54,0.08)" : "")},
            });
            continue;
        }
        if(line.startsWith("Total:") || line.startsWith("=== ")) continue;
    }
    let title = chainName;
    if(successCount + errorCount > 0){
        title += " — " + successCount + " success";
        if(errorCount > 0) title += ", " + errorCount + " errors";
    }
    return {"table": [{"headers": headers, "rows": rows, "title": title}]};
}

function formatBytes(bytes){
    if(bytes === 0) return "0 B";
    let units = ["B", "KB", "MB", "GB", "TB"];
    let i = Math.floor(Math.log(bytes) / Math.log(1024));
    if(i >= units.length) i = units.length - 1;
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
}
