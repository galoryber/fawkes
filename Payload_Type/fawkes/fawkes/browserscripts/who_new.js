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
            return {"plaintext": "No active user sessions found"};
        }
        let headers = [
            {"plaintext": "user", "type": "string", "fillWidth": true},
            {"plaintext": "tty", "type": "string", "width": 140},
            {"plaintext": "login_time", "type": "string", "width": 180},
            {"plaintext": "from", "type": "string", "width": 160},
            {"plaintext": "status", "type": "string", "width": 120},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.status === "disconnected"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            } else if(e.status === "active"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "user": {"plaintext": e.user, "copyIcon": true},
                "tty": {"plaintext": e.tty},
                "login_time": {"plaintext": e.login_time},
                "from": {"plaintext": e.from, "copyIcon": true},
                "status": {"plaintext": e.status},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Active Sessions (" + data.length + ")",
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
