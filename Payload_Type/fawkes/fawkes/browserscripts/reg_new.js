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
        // Try to parse as JSON (search action returns JSON array)
        let data;
        try {
            data = JSON.parse(combined);
        } catch(e) {
            // Non-JSON output (read, write, delete actions) — render as plaintext
            return {"plaintext": combined};
        }
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Key Path", "type": "string", "fillWidth": true},
            {"plaintext": "Value Name", "type": "string", "width": 200},
            {"plaintext": "Value Data", "type": "string", "width": 300},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let keyStyle = {};
            let nameStyle = {};
            let dataStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
            // Highlight security-relevant registry paths
            let lowerPath = (e.key_path || "").toLowerCase();
            if(lowerPath.includes("run") || lowerPath.includes("startup") || lowerPath.includes("services")){
                keyStyle = {"color": "#e67e22", "fontWeight": "bold"};
            }
            if(lowerPath.includes("policies") || lowerPath.includes("security")){
                keyStyle = {"color": "#3498db", "fontWeight": "bold"};
            }
            rows.push({
                "Key Path": {"plaintext": e.key_path || "", "copyIcon": true, "cellStyle": keyStyle},
                "Value Name": {"plaintext": e.value_name || "(Default)", "copyIcon": true, "cellStyle": nameStyle},
                "Value Data": {"plaintext": e.value_data || "", "copyIcon": true, "cellStyle": dataStyle},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Registry Search \u2014 " + data.length + " matches",
            }]
        };
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
