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
            {key: "path", label: "File"},
            {key: "filename", label: "Filename"},
            {key: "size", label: "Size"},
            {key: "status", label: "Status"},
            {key: "chunks", label: "Chunks"},
            {key: "file_id", label: "File ID"},
        ];
        for(let i = 0; i < fields.length; i++){
            let f = fields[i];
            let val = data[f.key];
            if(val !== undefined && val !== ""){
                let style = {"fontFamily": "monospace"};
                if(f.key === "status"){
                    style.color = val === "complete" || val === "success" ? "#2ecc71" : "#e74c3c";
                    style.fontWeight = "bold";
                }
                rows.push({
                    "Property": {"plaintext": f.label, "cellStyle": {"fontWeight": "bold"}},
                    "Value": {"plaintext": String(val), "copyIcon": f.key === "file_id", "cellStyle": style},
                });
            }
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Download \u2014 " + (data.path || data.filename || "")}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
