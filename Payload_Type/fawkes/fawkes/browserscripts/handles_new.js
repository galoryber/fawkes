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

        let tables = [];

        // Type summary table
        if(data.summary && data.summary.length > 0){
            let summaryHeaders = [
                {"plaintext": "type", "type": "string", "fillWidth": true},
                {"plaintext": "count", "type": "number", "width": 100},
            ];
            let summaryRows = [];
            for(let j = 0; j < data.summary.length; j++){
                let s = data.summary[j];
                summaryRows.push({
                    "type": {"plaintext": s.type},
                    "count": {"plaintext": s.count},
                    "rowStyle": {},
                });
            }
            tables.push({
                "headers": summaryHeaders,
                "rows": summaryRows,
                "title": "Handle Type Summary (PID " + data.pid + ": " + (data.shown || data.total) + " of " + data.total + " handles)",
            });
        }

        // Handle detail table
        if(data.handles && data.handles.length > 0){
            let handleHeaders = [
                {"plaintext": "handle", "type": "string", "width": 90},
                {"plaintext": "type", "type": "string", "width": 200},
                {"plaintext": "name", "type": "string", "fillWidth": true},
            ];
            let handleRows = [];
            for(let j = 0; j < data.handles.length; j++){
                let h = data.handles[j];
                let rowStyle = {};
                if(h.type === "File"){
                    rowStyle = {"backgroundColor": "rgba(100,149,237,0.1)"};
                } else if(h.type === "Key"){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                } else if(h.type === "Process" || h.type === "Thread"){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
                }
                handleRows.push({
                    "handle": {"plaintext": "0x" + h.handle.toString(16).toUpperCase().padStart(4, '0')},
                    "type": {"plaintext": h.type},
                    "name": {"plaintext": h.name || "(unnamed)"},
                    "rowStyle": rowStyle,
                });
            }
            tables.push({
                "headers": handleHeaders,
                "rows": handleRows,
                "title": "Handle Details (" + data.handles.length + " shown)",
            });
        }

        if(data.note){
            tables.push({
                "headers": [{"plaintext": "note", "type": "string", "fillWidth": true}],
                "rows": [{"note": {"plaintext": data.note}, "rowStyle": {}}],
                "title": "Note",
            });
        }

        if(tables.length === 0){
            return {"plaintext": combined};
        }

        return {"table": tables};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
