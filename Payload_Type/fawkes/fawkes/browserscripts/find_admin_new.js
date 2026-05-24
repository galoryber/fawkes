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
    if(combined.includes("=== Lateral Movement Chain") || combined.includes("[Step ") && combined.includes("auto-move")){
        return renderChainTable(combined, "Auto-Move Lateral Chain");
    }
    try {
        let data = JSON.parse(combined);
        if(data.length === 0){
            return {"plaintext": "No results — no hosts responded"};
        }
        let headers = [
            {"plaintext": "Host", "type": "string", "fillWidth": true},
            {"plaintext": "Method", "type": "string", "width": 100},
            {"plaintext": "Admin", "type": "string", "width": 100},
            {"plaintext": "Message", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let adminCount = 0;
        for(let j = 0; j < data.length; j++){
            let entry = data[j];
            let rowStyle = {};
            let adminText = "No";
            let adminStyle = {};
            if(entry.admin){
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.15)"};
                adminText = "YES";
                adminStyle = {"fontWeight": "bold", "color": "#4caf50"};
                adminCount++;
            }
            if(entry.message && entry.message.toLowerCase().includes("error")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.06)"};
            }
            rows.push({
                "Host": {"plaintext": entry.host, "copyIcon": true},
                "Method": {"plaintext": entry.method || ""},
                "Admin": {"plaintext": adminText, "cellStyle": adminStyle},
                "Message": {"plaintext": entry.message || ""},
                "rowStyle": rowStyle,
            });
        }
        let title = "Admin Check (" + data.length + " hosts, " + adminCount + " admin)";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
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
        if(line.length > 5 && !line.startsWith("Could not")){
            rows.push({
                "Status": {"plaintext": "INFO", "cellStyle": {"color": "#ff9800"}},
                "Command": {"plaintext": ""},
                "Detail": {"plaintext": line},
                "rowStyle": {},
            });
        }
    }
    let title = chainName;
    if(successCount + errorCount > 0){
        title += " — " + successCount + " success";
        if(errorCount > 0) title += ", " + errorCount + " errors";
    }
    return {"table": [{"headers": headers, "rows": rows, "title": title}]};
}
