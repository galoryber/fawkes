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
        if(typeof data !== "object" || data === null){
            return {"plaintext": combined};
        }
        let success = data.success === true || data.success === "true";
        let borderColor = success ? "#4caf50" : "#f44336";
        let bgColor = success ? "rgba(76,175,80,0.08)" : "rgba(244,67,54,0.08)";
        let statusText = success ? "Credentials Captured" : "Prompt Cancelled";
        let headers = [
            {"plaintext": "Field", "type": "string", "width": 120},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        if(data.username !== undefined){
            rows.push({
                "Field": {"plaintext": "Username", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.username, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                "rowStyle": {"backgroundColor": bgColor},
            });
        }
        if(data.password !== undefined){
            let passDisplay = success ? data.password : "N/A";
            rows.push({
                "Field": {"plaintext": "Password", "cellStyle": {"fontWeight": "bold"}},
                "Value": {
                    "plaintext": passDisplay,
                    "copyIcon": success,
                    "cellStyle": {"fontFamily": "monospace", "color": success ? borderColor : "#999"},
                },
                "rowStyle": {"backgroundColor": bgColor},
            });
        }
        if(data.domain !== undefined && data.domain !== ""){
            rows.push({
                "Field": {"plaintext": "Domain", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.domain, "copyIcon": true},
                "rowStyle": {"backgroundColor": bgColor},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": statusText,
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
