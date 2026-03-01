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
            return {"plaintext": "No matches found"};
        }
        let headers = [
            {"plaintext": "key_path", "type": "string", "fillWidth": true},
            {"plaintext": "value_name", "type": "string", "width": 200},
            {"plaintext": "value_data", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.value_name){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.1)"};
            }
            rows.push({
                "key_path": {"plaintext": e.key_path, "copyIcon": true},
                "value_name": {"plaintext": e.value_name || "(key match)"},
                "value_data": {"plaintext": e.value_data || "", "copyIcon": e.value_data ? true : false},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Registry Search — " + data.length + " match(es)",
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
