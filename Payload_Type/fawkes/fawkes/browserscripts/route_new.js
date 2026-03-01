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
            return {"plaintext": "No routes found"};
        }
        let headers = [
            {"plaintext": "destination", "type": "string", "fillWidth": true},
            {"plaintext": "gateway", "type": "string", "width": 160},
            {"plaintext": "netmask", "type": "string", "width": 160},
            {"plaintext": "interface", "type": "string", "width": 150},
            {"plaintext": "metric", "type": "number", "width": 80},
            {"plaintext": "flags", "type": "string", "width": 80},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.destination === "0.0.0.0" || e.destination === "default"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "destination": {"plaintext": e.destination, "copyIcon": true},
                "gateway": {"plaintext": e.gateway || "*"},
                "netmask": {"plaintext": e.netmask || ""},
                "interface": {"plaintext": e.interface || ""},
                "metric": {"plaintext": String(e.metric || 0)},
                "flags": {"plaintext": e.flags || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Routing Table (" + data.length + " entries)",
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
