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
            return {"plaintext": "No results"};
        }
        // Detect format: spray results (have "success" field) vs enumerate results (have "status" field like "exists"/"asrep"/"not_found")
        if(data[0].status !== undefined && (data[0].status === "exists" || data[0].status === "asrep" || data[0].status === "not_found")){
            // Enumerate mode
            let valid = data.filter(e => e.status === "exists" || e.status === "asrep").length;
            let asrep = data.filter(e => e.status === "asrep").length;
            let statusColors = {
                "exists": "rgba(0,200,0,0.15)",
                "asrep": "rgba(255,165,0,0.2)",
                "not_found": "rgba(255,255,255,0)",
            };
            let headers = [
                {"plaintext": "username", "type": "string", "fillWidth": true},
                {"plaintext": "status", "type": "string", "width": 100},
                {"plaintext": "message", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                let rowStyle = {};
                if(statusColors[e.status] !== undefined){
                    rowStyle = {"backgroundColor": statusColors[e.status]};
                }
                rows.push({
                    "username": {"plaintext": e.username, "copyIcon": true},
                    "status": {"plaintext": e.status},
                    "message": {"plaintext": e.message || ""},
                    "rowStyle": rowStyle,
                });
            }
            let title = "User Enumeration — " + valid + "/" + data.length + " valid";
            if(asrep > 0) title += " (" + asrep + " AS-REP roastable)";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        } else {
            // Spray mode
            let valid = data.filter(e => e.success).length;
            let locked = data.filter(e => !e.success && (e.message.includes("locked") || e.message.includes("REVOKED"))).length;
            let headers = [
                {"plaintext": "username", "type": "string", "fillWidth": true},
                {"plaintext": "result", "type": "string", "width": 80},
                {"plaintext": "message", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                let rowStyle = {};
                let result = "failed";
                if(e.success){
                    rowStyle = {"backgroundColor": "rgba(0,200,0,0.2)"};
                    result = "VALID";
                } else if(e.message.includes("locked") || e.message.includes("REVOKED")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                    result = "LOCKED";
                } else if(e.message.includes("expired") || e.message.includes("change password")){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                    result = "EXPIRED";
                }
                rows.push({
                    "username": {"plaintext": e.username, "copyIcon": true},
                    "result": {"plaintext": result},
                    "message": {"plaintext": e.message},
                    "rowStyle": rowStyle,
                });
            }
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Password Spray — " + valid + " valid, " + locked + " locked, " + (data.length - valid - locked) + " failed",
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
