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
            return {"plaintext": "No audit policy entries found"};
        }
        let headers = [
            {"plaintext": "category", "type": "string", "width": 200},
            {"plaintext": "subcategory", "type": "string", "fillWidth": true},
            {"plaintext": "setting", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.setting === "No Auditing"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            } else if(e.setting === "Success and Failure"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "category": {"plaintext": e.category},
                "subcategory": {"plaintext": e.subcategory},
                "setting": {"plaintext": e.setting},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Audit Policy (" + data.length + " subcategories)",
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
