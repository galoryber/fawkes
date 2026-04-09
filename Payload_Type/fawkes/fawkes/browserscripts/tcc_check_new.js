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
        let data;
        try { data = JSON.parse(combined); } catch(e) { return {"plaintext": combined}; }
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No TCC entries found"};
        }
        let headers = [
            {"plaintext": "Service", "type": "string", "width": 250},
            {"plaintext": "Client App", "type": "string", "fillWidth": true},
            {"plaintext": "Allowed", "type": "string", "width": 100},
            {"plaintext": "Auth Reason", "type": "string", "width": 200},
        ];
        let rows = [];
        let allowedCount = 0;
        let deniedCount = 0;
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let allowed = e.allowed;
            let allowedText = "";
            let cellStyle = {};
            if(allowed === true || allowed === "true" || allowed === 1 || allowed === "1"){
                allowedText = "YES";
                cellStyle = {"color": "#2ecc71", "fontWeight": "bold"};
                allowedCount++;
            } else {
                allowedText = "NO";
                cellStyle = {"color": "#e74c3c", "fontWeight": "bold"};
                deniedCount++;
            }
            let rowStyle = {};
            rows.push({
                "Service": {"plaintext": e.service || "Unknown", "copyIcon": true},
                "Client App": {"plaintext": e.client || "Unknown", "copyIcon": true},
                "Allowed": {"plaintext": allowedText, "cellStyle": cellStyle},
                "Auth Reason": {"plaintext": e.auth_reason || "N/A"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "TCC Permissions (" + data.length + " entries \u2014 " + allowedCount + " allowed, " + deniedCount + " denied)",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
