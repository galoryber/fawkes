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
            return {"plaintext": "No AS-REP roastable accounts found"};
        }
        let roasted = data.filter(e => e.status === "roasted").length;
        let headers = [
            {"plaintext": "account", "type": "string", "width": 200},
            {"plaintext": "etype", "type": "string", "width": 100},
            {"plaintext": "status", "type": "string", "width": 80},
            {"plaintext": "hash", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.status === "roasted"){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.15)"};
            } else if(e.status === "failed"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
            }
            rows.push({
                "account": {"plaintext": e.account, "copyIcon": true},
                "etype": {"plaintext": e.etype || ""},
                "status": {"plaintext": e.status},
                "hash": {"plaintext": e.hash ? e.hash.substring(0, 60) + "..." : (e.error || ""), "copyIcon": e.hash ? true : false},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "AS-REP Roast — " + roasted + "/" + data.length + " hashes extracted",
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
