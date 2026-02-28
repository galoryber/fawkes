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
        let data = JSON.parse(combined);
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No shares found"};
        }
        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "type", "type": "string", "width": 120},
            {"plaintext": "path", "type": "string", "fillWidth": true},
            {"plaintext": "remark", "type": "string", "fillWidth": true},
            {"plaintext": "host", "type": "string", "width": 140},
            {"plaintext": "provider", "type": "string", "width": 160},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.type && e.type.includes("Admin")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
            } else if(e.type === "IPC"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "name": {"plaintext": e.name || "", "copyIcon": true},
                "type": {"plaintext": e.type || ""},
                "path": {"plaintext": e.path || ""},
                "remark": {"plaintext": e.remark || ""},
                "host": {"plaintext": e.host || ""},
                "provider": {"plaintext": e.provider || ""},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Network Shares (" + data.length + ")",
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
