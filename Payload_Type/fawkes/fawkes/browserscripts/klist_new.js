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
            return {"plaintext": "No Kerberos tickets cached"};
        }
        let headers = [
            {"plaintext": "#", "type": "number", "width": 50},
            {"plaintext": "client", "type": "string", "width": 200},
            {"plaintext": "server", "type": "string", "fillWidth": true},
            {"plaintext": "encryption", "type": "string", "width": 110},
            {"plaintext": "end", "type": "string", "width": 160},
            {"plaintext": "status", "type": "string", "width": 80},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.status === "EXPIRED"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.server && e.server.toLowerCase().startsWith("krbtgt/")){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "#": {"plaintext": String(e.index)},
                "client": {"plaintext": e.client || "-"},
                "server": {"plaintext": e.server || "-", "copyIcon": true},
                "encryption": {"plaintext": e.encryption || "-"},
                "end": {"plaintext": e.end || "-"},
                "status": {"plaintext": e.status || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Kerberos Ticket Cache (" + data.length + " tickets)",
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
