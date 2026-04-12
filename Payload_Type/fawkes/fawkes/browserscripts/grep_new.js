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
        // Try JSON output (structured grep results)
        let data;
        try { data = JSON.parse(combined); } catch(e) {
            // Plain text grep output — show with match count
            let lines = combined.split("\n").filter(l => l.trim().length > 0);
            let title = "Grep Results \u2014 " + lines.length + " matches";
            return {"plaintext": combined, "title": title};
        }
        if(!Array.isArray(data)){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "File", "type": "string", "width": 300},
            {"plaintext": "Line", "type": "number", "width": 60},
            {"plaintext": "Match", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let m = data[i];
            rows.push({
                "File": {"plaintext": m.file || m.path || "", "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Line": {"plaintext": String(m.line || m.line_number || ""), "cellStyle": {"fontFamily": "monospace"}},
                "Match": {"plaintext": m.match || m.text || m.content || "", "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em", "whiteSpace": "pre-wrap"}},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Grep Results \u2014 " + data.length + " matches"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
