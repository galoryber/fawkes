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
        // Handle recording results
        if(data.action === "record"){
            let recHeaders = [
                {"plaintext": "Property", "type": "string", "width": 150},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let recRows = [];
            let stopColor = data.stopped_by === "jobkill" ? "#ff9800" : "#4caf50";
            recRows.push({
                "Property": {"plaintext": "Frames Captured", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": String(data.frames_captured || 0), "cellStyle": {"fontFamily": "monospace", "fontWeight": "bold", "fontSize": "1.1em"}},
            });
            recRows.push({
                "Property": {"plaintext": "Duration", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.actual_duration || "unknown"},
            });
            recRows.push({
                "Property": {"plaintext": "Stopped By", "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": data.stopped_by || "unknown", "cellStyle": {"color": stopColor}},
            });
            return {"table": [{"headers": recHeaders, "rows": recRows, "title": "\ud83c\udfa5 Screen Recording Complete"}]};
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
