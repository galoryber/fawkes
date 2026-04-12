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
        if(data.status){
            let statusColor = data.status === "success" ? "#2ecc71" : "#e74c3c";
            rows.push({
                "Property": {"plaintext": "Status", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.status, "cellStyle": {"color": statusColor, "fontWeight": "bold"}},
            });
        }
        if(data.width && data.height){
            rows.push({
                "Property": {"plaintext": "Resolution", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.width + " x " + data.height, "cellStyle": {"fontFamily": "monospace"}},
            });
        }
        if(data.size){
            rows.push({
                "Property": {"plaintext": "Size", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": String(data.size), "cellStyle": {"fontFamily": "monospace"}},
            });
        }
        if(data.file_id){
            rows.push({
                "Property": {"plaintext": "File ID", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.file_id, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Screenshot Captured"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
