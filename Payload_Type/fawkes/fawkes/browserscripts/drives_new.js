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
            return {"plaintext": "No drives found"};
        }
        let headers = [
            {"plaintext": "drive", "type": "string", "width": 200},
            {"plaintext": "type", "type": "string", "width": 120},
            {"plaintext": "label", "type": "string", "fillWidth": true},
            {"plaintext": "free (GB)", "type": "number", "width": 120},
            {"plaintext": "total (GB)", "type": "number", "width": 120},
            {"plaintext": "used %", "type": "number", "width": 90},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let usePct = "-";
            let rowStyle = {};
            if(e.total_gb > 0){
                usePct = Math.round((1 - e.free_gb / e.total_gb) * 100);
                if(usePct > 90){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                } else if(usePct > 75){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                }
            }
            rows.push({
                "drive": {"plaintext": e.drive},
                "type": {"plaintext": e.type},
                "label": {"plaintext": e.label || "-"},
                "free (GB)": {"plaintext": e.free_gb >= 0 ? e.free_gb.toFixed(1) : "-"},
                "total (GB)": {"plaintext": e.total_gb >= 0 ? e.total_gb.toFixed(1) : "-"},
                "used %": {"plaintext": usePct},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Drives (" + data.length + " volumes)",
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
