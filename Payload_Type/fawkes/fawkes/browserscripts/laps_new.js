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
            return {"plaintext": "No LAPS passwords found"};
        }
        let headers = [
            {"plaintext": "computer", "type": "string", "width": 180},
            {"plaintext": "fqdn", "type": "string", "width": 250},
            {"plaintext": "version", "type": "string", "width": 80},
            {"plaintext": "account", "type": "string", "width": 140},
            {"plaintext": "password", "type": "string", "fillWidth": true},
            {"plaintext": "expiry_status", "type": "string", "width": 140},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.expiry_status === "EXPIRED"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.version === "v2-encrypted"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            } else if(e.password){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.08)"};
            }
            rows.push({
                "computer": {"plaintext": e.computer || "-"},
                "fqdn": {"plaintext": e.fqdn || "-"},
                "version": {"plaintext": e.version || "-"},
                "account": {"plaintext": e.account || "-"},
                "password": {"plaintext": e.password || "-", "copyIcon": true},
                "expiry_status": {"plaintext": e.expiry_status || (e.expires || "-")},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "LAPS Passwords (" + data.length + " entries)",
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
