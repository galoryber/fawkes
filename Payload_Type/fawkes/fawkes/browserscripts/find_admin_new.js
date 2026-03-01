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
        let adminCount = data.filter(e => e.admin).length;
        let headers = [
            {"plaintext": "host", "type": "string", "fillWidth": true},
            {"plaintext": "method", "type": "string", "width": 80},
            {"plaintext": "admin", "type": "string", "width": 80},
            {"plaintext": "message", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.admin){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.2)"};
            } else if(e.message === "auth failed"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
            }
            rows.push({
                "host": {"plaintext": e.host, "copyIcon": true},
                "method": {"plaintext": e.method},
                "admin": {"plaintext": e.admin ? "YES" : "no"},
                "message": {"plaintext": e.message || (e.admin ? "ADMIN" : "")},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Admin Sweep — " + adminCount + "/" + data.length + " hosts with admin access",
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
