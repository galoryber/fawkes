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
            return {"plaintext": "No active sessions"};
        }
        let hasTransport = data.some(e => e.transport && e.transport !== "");
        let headers = [
            {"plaintext": "client", "type": "string", "fillWidth": true},
            {"plaintext": "user", "type": "string", "width": 200},
            {"plaintext": "time", "type": "string", "width": 100},
            {"plaintext": "idle", "type": "string", "width": 100},
        ];
        if(hasTransport){
            headers.splice(2, 0, {"plaintext": "opens", "type": "number", "width": 80});
            headers.push({"plaintext": "transport", "type": "string", "width": 200});
        }
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let row = {
                "client": {"plaintext": e.client, "copyIcon": true},
                "user": {"plaintext": e.user, "copyIcon": true},
                "time": {"plaintext": e.time},
                "idle": {"plaintext": e.idle},
            };
            if(hasTransport){
                row["opens"] = {"plaintext": String(e.opens || 0)};
                row["transport"] = {"plaintext": e.transport || ""};
            }
            rows.push(row);
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "SMB Sessions (" + data.length + ")",
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
