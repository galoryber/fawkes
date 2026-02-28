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
            return {"plaintext": "No trust relationships found"};
        }
        let headers = [
            {"plaintext": "partner", "type": "string", "width": 220},
            {"plaintext": "direction", "type": "string", "width": 110},
            {"plaintext": "category", "type": "string", "width": 110},
            {"plaintext": "type", "type": "string", "width": 160},
            {"plaintext": "attributes", "type": "string", "fillWidth": true},
            {"plaintext": "risk", "type": "string", "width": 250},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.risk){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.direction === "Bidirectional"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.10)"};
            }
            rows.push({
                "partner": {"plaintext": e.partner || "-", "copyIcon": true},
                "direction": {"plaintext": e.direction || "-"},
                "category": {"plaintext": e.category || "-"},
                "type": {"plaintext": e.type || "-"},
                "attributes": {"plaintext": e.attributes || "-"},
                "risk": {"plaintext": e.risk || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Domain Trusts (" + data.length + " found)",
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
