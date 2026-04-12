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
        let headers = [
            {"plaintext": "Property", "type": "string", "width": 120},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let fields = [
            {key: "action", label: "Action"},
            {key: "input_file", label: "Input"},
            {key: "output_file", label: "Output"},
            {key: "input_size", label: "Input Size"},
            {key: "output_size", label: "Output Size"},
        ];
        for(let i = 0; i < fields.length; i++){
            let f = fields[i];
            let val = data[f.key];
            if(val !== undefined && val !== ""){
                rows.push({
                    "Property": {"plaintext": f.label, "cellStyle": {"fontWeight": "bold"}},
                    "Value": {"plaintext": String(val), "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                });
            }
        }
        // Show result/output data in collapsible format
        if(data.result || data.output || data.data){
            let result = data.result || data.output || data.data;
            if(result.length > 200){
                rows.push({
                    "Property": {"plaintext": "Result", "cellStyle": {"fontWeight": "bold"}},
                    "Value": {"plaintext": result.substring(0, 200) + "...", "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em", "wordBreak": "break-all"}},
                });
            } else {
                rows.push({
                    "Property": {"plaintext": "Result", "cellStyle": {"fontWeight": "bold"}},
                    "Value": {"plaintext": result, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "wordBreak": "break-all"}},
                });
            }
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        let title = "Base64 " + (data.action || "Result");
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
