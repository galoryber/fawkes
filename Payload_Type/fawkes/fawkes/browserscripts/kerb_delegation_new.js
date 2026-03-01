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
            return {"plaintext": "No delegation configurations found"};
        }
        let headers = [
            {"plaintext": "account", "type": "string", "width": 180},
            {"plaintext": "delegation_type", "type": "string", "width": 120},
            {"plaintext": "mode", "type": "string", "width": 160},
            {"plaintext": "targets", "type": "string", "fillWidth": true},
            {"plaintext": "risk", "type": "string", "width": 250},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.delegation_type === "Unconstrained"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.s4u2self){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            } else if(e.delegation_type === "Protected"){
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.08)"};
            }
            if(e.disabled){
                rowStyle = {"backgroundColor": "rgba(128,128,128,0.15)"};
            }
            let targetsStr = "-";
            if(e.targets && e.targets.length > 0){
                targetsStr = e.targets.join(", ");
            }
            let acctDisplay = e.account || "-";
            if(e.disabled){
                acctDisplay += " [DISABLED]";
            }
            rows.push({
                "account": {"plaintext": acctDisplay, "copyIcon": true},
                "delegation_type": {"plaintext": e.delegation_type || "-"},
                "mode": {"plaintext": e.mode || "-"},
                "targets": {"plaintext": targetsStr},
                "risk": {"plaintext": e.risk || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Kerberos Delegation (" + data.length + " entries)",
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
