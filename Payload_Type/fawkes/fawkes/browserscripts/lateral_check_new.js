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
            return {"plaintext": "No results"};
        }
        let headers = [
            {"plaintext": "host", "type": "string", "fillWidth": true},
            {"plaintext": "available", "type": "string", "fillWidth": true},
            {"plaintext": "suggested", "type": "string", "fillWidth": true},
            {"plaintext": "total_open", "type": "number", "width": 80},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.total_open >= 3){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.15)"};
            } else if(e.total_open === 0){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
            }
            rows.push({
                "host": {"plaintext": e.host, "copyIcon": true},
                "available": {"plaintext": e.available ? e.available.join(", ") : "none"},
                "suggested": {"plaintext": e.suggested ? e.suggested.join(", ") : "-"},
                "total_open": {"plaintext": String(e.total_open)},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Lateral Movement Check — " + data.length + " host(s)",
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
