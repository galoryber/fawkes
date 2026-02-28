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
            return {"plaintext": "No login history found"};
        }
        let headers = [
            {"plaintext": "user", "type": "string", "fillWidth": true},
            {"plaintext": "tty", "type": "string", "width": 130},
            {"plaintext": "from", "type": "string", "width": 160},
            {"plaintext": "login_time", "type": "string", "width": 200},
            {"plaintext": "duration", "type": "string", "width": 100},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            rows.push({
                "user": {"plaintext": e.user, "copyIcon": true},
                "tty": {"plaintext": e.tty || "-"},
                "from": {"plaintext": e.from || "-", "copyIcon": true},
                "login_time": {"plaintext": e.login_time || "-"},
                "duration": {"plaintext": e.duration || "-"},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Login History (" + data.length + " entries)",
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
