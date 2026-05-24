function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = "";
    for(let i = 0; i < responses.length; i++){
        combined += responses[i];
    }
    if(combined.includes("=== Credential Harvest Chain") || combined.includes("=== Full Credential Sweep")){
        return renderChainTable(combined, combined.includes("Full Credential Sweep") ? "Full Credential Sweep" : "Credential Harvest Chain");
    }
    try {
        let lines = combined.split("\n");
        let entries = [];
        let currentCategory = "";
        let currentSource = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^={10,}/)) continue;
            let majorMatch = trimmed.match(/^(System Credential Files|Cloud & Infrastructure Credentials|Application Credentials & Configs|Shell History Credential Scan|Windows Credential Sources)$/);
            if(majorMatch){
                currentCategory = majorMatch[1];
                continue;
            }
            let subMatch = trimmed.match(/^---\s+(.+?)\s+---/);
            if(subMatch){
                currentSource = subMatch[1];
                continue;
            }
            let fileMatch = trimmed.match(/^\[FILE\]\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(fileMatch){
                entries.push({category: currentCategory, source: currentSource, type: "File", path: fileMatch[1], detail: fileMatch[2] + " bytes"});
                continue;
            }
            let envMatch = trimmed.match(/^\[ENV\]\s+(\S+?)=(.*)/);
            if(envMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Env", path: envMatch[1], detail: envMatch[2]});
                continue;
            }
            let tokenMatch = trimmed.match(/^\[TOKEN\]\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(tokenMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Token", path: tokenMatch[1], detail: tokenMatch[2] + " bytes"});
                continue;
            }
            let dirMatch = trimmed.match(/^\[DIR\]\s+(\S+)/);
            if(dirMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Dir", path: dirMatch[1], detail: ""});
                continue;
            }
            let legacyMatch = trimmed.match(/^\[LEGACY\]\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(legacyMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Legacy", path: legacyMatch[1], detail: legacyMatch[2] + " bytes"});
                continue;
            }
            let valMatch = trimmed.match(/^Value:\s+(.*)/);
            if(valMatch){
                entries.push({category: currentCategory, source: currentSource, type: "Credential", path: "", detail: valMatch[1]});
                continue;
            }
            if(currentSource && (currentSource.includes("shadow") || currentSource.includes("passwd"))){
                let shadowMatch = trimmed.match(/^(\S+?):(\$.+)/);
                if(shadowMatch){
                    entries.push({category: currentCategory, source: currentSource, type: "Hash", path: shadowMatch[1], detail: shadowMatch[2].substring(0, 40) + "..."});
                    continue;
                }
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
            {"plaintext": "actions", "type": "button", "width": 80, "disableSort": true},
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
            let actionButton = null;
            if((e.type === "File" || e.type === "Token" || e.type === "Legacy") && e.path.startsWith("/")){
                actionButton = {
                    "name": "cat",
                    "type": "task",
                    "ui_feature": "cat",
                    "startIcon": "visibility",
                    "hoverText": "Read file: " + e.path,
                    "parameters": e.path,
                };
            } else if(e.type === "Dir" && e.path.startsWith("/")){
                actionButton = {
                    "name": "ls",
                    "type": "task",
                    "ui_feature": "file_browser:list",
                    "startIcon": "list",
                    "hoverText": "List directory: " + e.path,
                    "parameters": {"full_path": e.path},
                };
            }
            rows.push({
                "actions": actionButton ? {"button": actionButton} : {"plaintext": ""},
                "Source": {"plaintext": e.source},
                "Type": {"plaintext": e.type, "cellStyle": typeStyle},
                "Path / Name": {"plaintext": e.path, "copyIcon": e.path.length > 0, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Detail": {"plaintext": e.detail, "copyIcon": e.detail.length > 0, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "rowStyle": rowStyle
            });
        }
        let title = "Credential Harvest — " + entries.length + " findings";
        if(credCount > 0) title += " (" + credCount + " credentials)";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        return {'plaintext': combined};
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
    let credentialHints = [];
    for(let i = 0; i < lines.length; i++){
        let line = lines[i].trim();
        if(!line || line.match(/^={3,}$/)) continue;
        let taskMatch = line.match(/^\[(SUCCESS|ERROR|unknown)\]\s+(\S+):\s*(.*)/);
        if(taskMatch){
            let status = taskMatch[1];
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
        let credMatch = line.match(/→\s+(\d+)\s+potential credentials found/);
        if(credMatch){
            credentialHints.push(parseInt(credMatch[1]));
            continue;
        }
        let summaryMatch = line.match(/^Subtasks:\s+(\d+)\s+success,\s+(\d+)\s+errors/);
        if(summaryMatch) continue;
        if(line.startsWith("=== ")) continue;
    }
    let totalCreds = credentialHints.reduce((a, b) => a + b, 0);
    let title = chainName + " — " + successCount + " success";
    if(errorCount > 0) title += ", " + errorCount + " errors";
    if(totalCreds > 0) title += " (" + totalCreds + " credentials found)";
    return {"table": [{"headers": headers, "rows": rows, "title": title}]};
}
