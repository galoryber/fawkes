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
            return {"plaintext": "No certificates found"};
        }
        let headers = [
            {"plaintext": "subject", "type": "string", "fillWidth": true},
            {"plaintext": "issuer", "type": "string", "width": 200},
            {"plaintext": "store", "type": "string", "width": 120},
            {"plaintext": "location", "type": "string", "width": 120},
            {"plaintext": "not_before", "type": "string", "width": 110},
            {"plaintext": "not_after", "type": "string", "width": 110},
            {"plaintext": "has_private_key", "type": "string", "width": 80},
            {"plaintext": "thumbprint", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.expired){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.has_private_key){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            }
            rows.push({
                "subject": {"plaintext": e.subject, "copyIcon": true},
                "issuer": {"plaintext": e.issuer},
                "store": {"plaintext": e.store},
                "location": {"plaintext": e.location},
                "not_before": {"plaintext": e.not_before || ""},
                "not_after": {"plaintext": e.not_after || ""},
                "has_private_key": {"plaintext": e.has_private_key ? "YES" : ""},
                "thumbprint": {"plaintext": e.thumbprint, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Certificates (" + data.length + ")",
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
