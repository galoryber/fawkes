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
            return {"plaintext": "No security products detected"};
        }
        // Count unique products
        let unique = {};
        for(let e of data){ unique[e.product] = e.category; }
        let catCount = {};
        for(let p in unique){ catCount[unique[p]] = (catCount[unique[p]]||0) + 1; }
        let catSummary = Object.entries(catCount).map(([k,v]) => v + " " + k).join(", ");
        let catColors = {
            "EDR": "rgba(255,0,0,0.15)",
            "AV": "rgba(255,165,0,0.12)",
            "Logging": "rgba(100,149,237,0.12)",
            "Firewall": "rgba(200,200,200,0.12)",
        };
        let headers = [
            {"plaintext": "product", "type": "string", "fillWidth": true},
            {"plaintext": "vendor", "type": "string", "width": 120},
            {"plaintext": "category", "type": "string", "width": 80},
            {"plaintext": "process", "type": "string", "width": 200},
            {"plaintext": "pid", "type": "number", "width": 70},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(catColors[e.category]){
                rowStyle = {"backgroundColor": catColors[e.category]};
            }
            rows.push({
                "product": {"plaintext": e.product},
                "vendor": {"plaintext": e.vendor},
                "category": {"plaintext": e.category},
                "process": {"plaintext": e.process, "copyIcon": true},
                "pid": {"plaintext": String(e.pid)},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Security Products — " + Object.keys(unique).length + " unique (" + catSummary + ")",
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
