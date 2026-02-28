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
            return {"plaintext": "No logon sessions found"};
        }
        let headers = [
            {"plaintext": "session_id", "type": "number", "width": 80},
            {"plaintext": "username", "type": "string", "fillWidth": true},
            {"plaintext": "domain", "type": "string", "width": 150},
            {"plaintext": "station", "type": "string", "width": 120},
            {"plaintext": "state", "type": "string", "width": 110},
            {"plaintext": "client", "type": "string", "width": 130},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.state === "Active"){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.15)"};
            } else if(e.state === "Disconnected"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            }
            rows.push({
                "session_id": {"plaintext": String(e.session_id)},
                "username": {"plaintext": e.username || "(none)", "copyIcon": e.username ? true : false},
                "domain": {"plaintext": e.domain || "-"},
                "station": {"plaintext": e.station || "-"},
                "state": {"plaintext": e.state},
                "client": {"plaintext": e.client || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Logon Sessions (" + data.length + ")",
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
