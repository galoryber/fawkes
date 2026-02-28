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
            return {"plaintext": "No logged-on users found"};
        }
        let headers = [
            {"plaintext": "username", "type": "string", "fillWidth": true},
            {"plaintext": "logon_domain", "type": "string", "width": 200},
            {"plaintext": "logon_server", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            rows.push({
                "username": {"plaintext": e.username, "copyIcon": true},
                "logon_domain": {"plaintext": e.logon_domain},
                "logon_server": {"plaintext": e.logon_server},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Logged-On Users (" + data.length + ")",
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
