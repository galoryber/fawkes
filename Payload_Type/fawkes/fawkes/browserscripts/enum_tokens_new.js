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
            return {"plaintext": "No tokens found"};
        }

        // Check if this is a "unique" result (has "count" field) or "list" result (has "pid")
        if(data[0].hasOwnProperty("count")){
            // Unique mode
            let headers = [
                {"plaintext": "user", "type": "string", "fillWidth": true},
                {"plaintext": "integrity", "type": "string", "width": 100},
                {"plaintext": "processes", "type": "number", "width": 90},
                {"plaintext": "sessions", "type": "string", "width": 100},
                {"plaintext": "examples", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                let rowStyle = {};
                if(e.integrity === "System"){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                } else if(e.integrity === "High"){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                }
                rows.push({
                    "user": {"plaintext": e.user, "copyIcon": true},
                    "integrity": {"plaintext": e.integrity},
                    "processes": {"plaintext": e.count},
                    "sessions": {"plaintext": (e.sessions || []).join(", ")},
                    "examples": {"plaintext": (e.processes || []).join(", ")},
                    "rowStyle": rowStyle,
                });
            }
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Unique Token Owners (" + data.length + ")",
                }]
            };
        } else {
            // List mode
            let headers = [
                {"plaintext": "pid", "type": "number", "width": 80},
                {"plaintext": "process", "type": "string", "fillWidth": true},
                {"plaintext": "user", "type": "string", "fillWidth": true},
                {"plaintext": "integrity", "type": "string", "width": 100},
                {"plaintext": "session", "type": "number", "width": 80},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                let rowStyle = {};
                if(e.integrity === "System"){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                } else if(e.integrity === "High"){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                } else if(e.integrity === "Low"){
                    rowStyle = {"backgroundColor": "rgba(128,128,128,0.15)"};
                }
                rows.push({
                    "pid": {"plaintext": e.pid, "copyIcon": true},
                    "process": {"plaintext": e.process},
                    "user": {"plaintext": e.user, "copyIcon": true},
                    "integrity": {"plaintext": e.integrity},
                    "session": {"plaintext": e.session},
                    "rowStyle": rowStyle,
                });
            }
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Process Tokens (" + data.length + " processes)",
                }]
            };
        }
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
