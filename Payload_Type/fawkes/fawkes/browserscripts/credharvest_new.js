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
        let currentSource = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^={10,}/)) continue;
            // Major section header (action): "System Credential Files", "Cloud & Infrastructure", etc.
            let majorMatch = trimmed.match(/^(System Credential Files|Cloud & Infrastructure Credentials|Application Credentials & Configs|Shell History Credential Scan|Windows Credential Sources)$/);
            if(majorMatch){
                currentCategory = majorMatch[1];
                continue;
            }
            // Sub-section: "--- AWS ---" or "--- /etc/shadow ---"
            let subMatch = trimmed.match(/^---\s+(.+?)\s+---/);
            if(subMatch){
                currentSource = subMatch[1];
                continue;
            }
            // File findings: "[FILE] /path (size bytes)"
            let fileMatch = trimmed.match(/^\[FILE\]\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(fileMatch){
                entries.push({category: currentCategory, source: currentSource, type: "File", path: fileMatch[1], detail: fileMatch[2] + " bytes"});
                continue;
            }
            // Env findings: "[ENV] KEY=VALUE"
            let envMatch = trimmed.match(/^\[ENV\]\s+(\S+?)=(.*)/);
            if(envMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Env", path: envMatch[1], detail: envMatch[2]});
                continue;
            }
            // Token findings: "[TOKEN] /path (size bytes)"
            let tokenMatch = trimmed.match(/^\[TOKEN\]\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(tokenMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Token", path: tokenMatch[1], detail: tokenMatch[2] + " bytes"});
                continue;
            }
            // Dir findings: "[DIR] /path"
            let dirMatch = trimmed.match(/^\[DIR\]\s+(\S+)/);
            if(dirMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Dir", path: dirMatch[1], detail: ""});
                continue;
            }
            // Legacy: "[LEGACY] path (size bytes)"
            let legacyMatch = trimmed.match(/^\[LEGACY\]\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(legacyMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Legacy", path: legacyMatch[1], detail: legacyMatch[2] + " bytes"});
                continue;
            }
            // History credential: "Value: credential_text"
            let valMatch = trimmed.match(/^Value:\s+(.*)/);
            if(valMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Credential", path: "", detail: valMatch[1]});
                continue;
            }
            // Shadow hash: "  user:$hash:..."
            if(currentSource && (currentSource.includes("shadow") || currentSource.includes("passwd"))){
                let shadowMatch = trimmed.match(/^(\S+?):(\$.+)/);
                if(shadowMatch){
                    entries.push({category: currentCategory, source: currentSource, type: "Hash", path: shadowMatch[1], detail: shadowMatch[2].substring(0, 40) + "..."});
                    continue;
                }
                // passwd entry
                let passwdMatch = trimmed.match(/^(\S+)\s+\(uid=(\d+)/);
                if(passwdMatch){
                    entries.push({category: currentCategory, source: currentSource, type: "Account", path: passwdMatch[1], detail: trimmed});
                }
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Source", "type": "string", "width": 150},
            {"plaintext": "Type", "type": "string", "width": 90},
            {"plaintext": "Path / Name", "type": "string", "width": 300},
            {"plaintext": "Detail", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        let credCount = 0;
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let typeStyle = {};
            let rowStyle = {};
            if(e.type === "Credential" || e.type === "Hash" || e.type === "Token"){
                typeStyle = {"color": "#d94f00", "fontWeight": "bold"};
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                credCount++;
            } else if(e.type === "Env"){
                typeStyle = {"color": "#ff8c00"};
                credCount++;
            }
            rows.push({
                "Source": {"plaintext": e.source},
                "Type": {"plaintext": e.type, "cellStyle": typeStyle},
                "Path / Name": {"plaintext": e.path, "copyIcon": e.path.length > 0, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Detail": {"plaintext": e.detail, "copyIcon": e.detail.length > 0, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "rowStyle": rowStyle
            });
        }
        let title = "Credential Harvest \u2014 " + entries.length + " findings";
        if(credCount > 0) title += " (" + credCount + " credentials)";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
