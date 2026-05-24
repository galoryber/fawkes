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
    if(combined.includes("[Step ") || combined.includes("=== Recon Chain")){
        return renderChainTable(combined, "Recon Chain");
    }
    try {
        let data = JSON.parse(combined);
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No files found"};
        }
        function formatSize(bytes){
            if(bytes < 1024) return bytes + "B";
            if(bytes < 1048576) return (bytes/1024).toFixed(1) + "KB";
            return (bytes/1048576).toFixed(1) + "MB";
        }
        let headers = [
            {"plaintext": "category", "type": "string", "width": 80},
            {"plaintext": "size", "type": "size", "width": 90},
            {"plaintext": "modified", "type": "string", "width": 130},
            {"plaintext": "path", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let catColors = {
            "cred": "rgba(255,0,0,0.15)",
            "config": "rgba(255,165,0,0.12)",
            "doc": "rgba(100,149,237,0.12)",
        };
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(catColors[e.category]){
                rowStyle = {"backgroundColor": catColors[e.category]};
            }
            rows.push({
                "category": {"plaintext": e.category},
                "size": {"plaintext": formatSize(e.size)},
                "modified": {"plaintext": e.modified || ""},
                "path": {"plaintext": e.path, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        let cats = {};
        for(let e of data){ cats[e.category] = (cats[e.category]||0) + 1; }
        let catSummary = Object.entries(cats).map(([k,v]) => v + " " + k).join(", ");
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "File Triage — " + data.length + " files (" + catSummary + ")",
            }]
        };
    } catch(error) {
        return {"plaintext": combined};
    }
}

function renderChainTable(text, chainName){
    let lines = text.split("\n");
    let headers = [
        {"plaintext": "Status", "type": "string", "width": 100},
        {"plaintext": "Step", "type": "string", "fillWidth": true},
    ];
    let rows = [];
    let successCount = 0;
    let errorCount = 0;
    for(let i = 0; i < lines.length; i++){
        let line = lines[i].trim();
        if(!line) continue;
        let stepMatch = line.match(/^\[Step (\d+\/\d+)\]\s+(.*)/);
        if(stepMatch){
            rows.push({
                "Status": {"plaintext": stepMatch[1], "cellStyle": {"fontWeight": "bold", "color": "#2196f3"}},
                "Step": {"plaintext": stepMatch[2]},
                "rowStyle": {"backgroundColor": "rgba(33,150,243,0.08)"},
            });
            continue;
        }
        let taskMatch = line.match(/^\[(SUCCESS|ERROR|success|error|unknown)\]\s+(.*)/);
        if(taskMatch){
            let status = taskMatch[1].toUpperCase();
            let isSuccess = status === "SUCCESS";
            if(isSuccess) successCount++;
            else errorCount++;
            rows.push({
                "Status": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": isSuccess ? "#4caf50" : "#f44336"}},
                "Step": {"plaintext": taskMatch[2]},
                "rowStyle": {"backgroundColor": isSuccess ? "rgba(76,175,80,0.08)" : "rgba(244,67,54,0.08)"},
            });
            continue;
        }
        if(line.startsWith("===") || line.startsWith("Total:") || line.startsWith("Subtasks:")){
            continue;
        }
        if(line.startsWith("Recon Chain") || line.startsWith("Credential Harvest") || line.startsWith("Auto-Move")){
            rows.push({
                "Status": {"plaintext": "INFO", "cellStyle": {"fontWeight": "bold", "color": "#ff9800"}},
                "Step": {"plaintext": line},
                "rowStyle": {"backgroundColor": "rgba(255,152,0,0.08)"},
            });
        }
    }
    let title = chainName;
    if(successCount + errorCount > 0){
        title += " — " + successCount + " success";
        if(errorCount > 0) title += ", " + errorCount + " errors";
    } else if(rows.length > 0){
        title += " — in progress";
    }
    return {"table": [{"headers": headers, "rows": rows, "title": title}]};
}
