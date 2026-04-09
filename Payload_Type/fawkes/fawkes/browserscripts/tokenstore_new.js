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
            return {"plaintext": "No tokens in store"};
        }
        let headers = [
            {"plaintext": "Token ID", "type": "number", "width": 100},
            {"plaintext": "PID", "type": "number", "width": 90},
            {"plaintext": "User", "type": "string", "fillWidth": true},
            {"plaintext": "Type", "type": "string", "width": 150},
            {"plaintext": "Impersonation Level", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let user = e.user || "N/A";
            let rowStyle = {};
            // Highlight SYSTEM tokens
            let lowerUser = user.toLowerCase();
            if(lowerUser === "system" || lowerUser === "nt authority\\system" || lowerUser === "nt authority\\local service" || lowerUser === "nt authority\\network service"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            }
            rows.push({
                "Token ID": {"plaintext": e.token_id, "copyIcon": true},
                "PID": {"plaintext": e.pid, "copyIcon": true},
                "User": {"plaintext": user, "copyIcon": true},
                "Type": {"plaintext": e.type || "N/A"},
                "Impersonation Level": {"plaintext": e.impersonation_level || "N/A"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Token Store (" + data.length + " tokens)",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
