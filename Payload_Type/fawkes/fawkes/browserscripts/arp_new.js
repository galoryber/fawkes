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
            return {"plaintext": "No ARP entries found"};
        }
        let headers = [
            {"plaintext": "ip", "type": "string", "fillWidth": true},
            {"plaintext": "mac", "type": "string", "width": 180},
            {"plaintext": "type", "type": "string", "width": 100},
            {"plaintext": "interface", "type": "string", "width": 150},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.type === "static"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "ip": {"plaintext": e.ip, "copyIcon": true},
                "mac": {"plaintext": e.mac, "copyIcon": true},
                "type": {"plaintext": e.type},
                "interface": {"plaintext": e.interface},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "ARP Table (" + data.length + " entries)",
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
