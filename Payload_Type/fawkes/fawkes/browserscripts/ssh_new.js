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

    let action = "";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            action = (params.action || "exec").toLowerCase();
        } catch(e){}
    }

    if(action === "check"){
        try {
            let data = JSON.parse(combined);
            let statusColor = data.overall_status === "pass" ? "#2ecc71" :
                              data.overall_status === "partial" ? "#f39c12" : "#e74c3c";
            let headers = [
                {"plaintext": "Check", "type": "string", "width": 160},
                {"plaintext": "Result", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            let fields = [
                ["Host", data.host],
                ["SSH Port", data.ssh_port],
                ["Banner", data.banner],
                ["Authentication", data.authentication],
                ["Shell Access", data.shell_access],
                ["Overall Status", data.overall_status],
                ["Recommendation", data.recommendation],
            ];
            for(let i = 0; i < fields.length; i++){
                let val = fields[i][1];
                if(!val) continue;
                let style = {};
                if(fields[i][0] === "Overall Status"){
                    style = {"color": statusColor, "fontWeight": "bold"};
                } else if(val === "pass" || val === "open"){
                    style = {"color": "#2ecc71"};
                } else if(val.startsWith("fail") || val === "closed" || val === "timeout"){
                    style = {"color": "#e74c3c"};
                } else if(val === "skipped" || val.startsWith("skipped")){
                    style = {"color": "#95a5a6"};
                }
                rows.push({
                    "Check": {"plaintext": fields[i][0], "cellStyle": {"fontWeight": "bold"}},
                    "Result": {"plaintext": val, "cellStyle": style},
                });
            }
            return {"table": [{"headers": headers, "rows": rows, "title": "SSH Check \u2014 " + data.host + " \u2014 " + data.overall_status.toUpperCase()}]};
        } catch(e){}
    }

    if(action === "tunnel-list"){
        try {
            let data = JSON.parse(combined);
            if(Array.isArray(data) && data.length > 0){
                let headers = [
                    {"plaintext": "ID", "type": "string", "width": 80},
                    {"plaintext": "Type", "type": "string", "width": 120},
                    {"plaintext": "Local", "type": "string", "width": 160},
                    {"plaintext": "Remote", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                for(let i = 0; i < data.length; i++){
                    let t = data[i];
                    rows.push({
                        "ID": {"plaintext": t.id || String(i), "cellStyle": {"fontFamily": "monospace"}},
                        "Type": {"plaintext": t.type || "", "cellStyle": {"fontWeight": "bold"}},
                        "Local": {"plaintext": t.local || t.local_addr || ""},
                        "Remote": {"plaintext": t.remote || t.remote_addr || ""},
                    });
                }
                return {"table": [{"headers": headers, "rows": rows, "title": "SSH Tunnels \u2014 " + data.length + " active"}]};
            }
        } catch(e){}
    }

    let lines = combined.split("\n").filter(l => l.length > 0);
    let title = "ssh";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            let parts = [];
            if(params.username) parts.push(params.username);
            if(params.host) parts.push(params.host);
            if(parts.length > 0) title += " \u2014 " + parts.join("@");
            if(params.action && params.action !== "exec") title += " [" + params.action + "]";
            if(params.command) title += " > " + params.command;
        } catch(e){}
    }
    title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
