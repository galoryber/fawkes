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
        if(data.length === 0){
            return {"plaintext": "No active connections found"};
        }
        let headers = [
            {"plaintext": "proto", "type": "string", "width": 70},
            {"plaintext": "local", "type": "string", "fillWidth": true},
            {"plaintext": "remote", "type": "string", "fillWidth": true},
            {"plaintext": "state", "type": "string", "width": 130},
            {"plaintext": "pid", "type": "number", "width": 80},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let conn = data[j];
            let localAddr = conn["local_ip"] + ":" + (conn["local_port"] || "*");
            let remoteAddr = conn["remote_ip"] + ":" + (conn["remote_port"] || "*");
            let rowStyle = {};
            // Highlight LISTEN in green, ESTABLISHED in blue
            if(conn["state"] === "LISTEN"){
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.1)"};
            } else if(conn["state"] === "ESTABLISHED"){
                rowStyle = {"backgroundColor": "rgba(33,150,243,0.1)"};
            }
            rows.push({
                "proto": {"plaintext": conn["proto"]},
                "local": {"plaintext": localAddr, "copyIcon": true},
                "remote": {"plaintext": remoteAddr, "copyIcon": true},
                "state": {"plaintext": conn["state"]},
                "pid": {"plaintext": conn["pid"] > 0 ? conn["pid"] : "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Network Connections (" + data.length + " total)",
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
