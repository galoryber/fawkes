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
            return {"plaintext": "No files found"};
        }
        function formatSize(bytes){
            if(bytes < 1024) return bytes + "B";
            if(bytes < 1048576) return (bytes/1024).toFixed(1) + "KB";
            return (bytes/1048576).toFixed(1) + "MB";
        }
        let headers = [
            {"plaintext": "category", "type": "string", "width": 80},
            {"plaintext": "size", "type": "size", "width": 90},
            {"plaintext": "modified", "type": "string", "width": 130},
            {"plaintext": "path", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let catColors = {
            "cred": "rgba(255,0,0,0.15)",
            "config": "rgba(255,165,0,0.12)",
            "doc": "rgba(100,149,237,0.12)",
        };
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(catColors[e.category]){
                rowStyle = {"backgroundColor": catColors[e.category]};
            }
            rows.push({
                "category": {"plaintext": e.category},
                "size": {"plaintext": formatSize(e.size)},
                "modified": {"plaintext": e.modified || ""},
                "path": {"plaintext": e.path, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        // Count by category
        let cats = {};
        for(let e of data){ cats[e.category] = (cats[e.category]||0) + 1; }
        let catSummary = Object.entries(cats).map(([k,v]) => v + " " + k).join(", ");
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "File Triage — " + data.length + " files (" + catSummary + ")",
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
