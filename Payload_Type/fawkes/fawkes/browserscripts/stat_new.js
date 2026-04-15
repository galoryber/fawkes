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
            {"plaintext": "Property", "type": "string", "width": 150},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        // Format file size with human-readable suffix
        let sizeStr = "";
        if(data.size !== undefined){
            let sz = Number(data.size);
            if(sz < 1024) sizeStr = sz + " B";
            else if(sz < 1024*1024) sizeStr = (sz/1024).toFixed(1) + " KB";
            else if(sz < 1024*1024*1024) sizeStr = (sz/(1024*1024)).toFixed(1) + " MB";
            else sizeStr = (sz/(1024*1024*1024)).toFixed(2) + " GB";
            sizeStr += " (" + sz.toLocaleString() + " bytes)";
        }
        let fields = [
            {key: "name", label: "File", style: {"fontWeight": "bold"}},
            {key: "type", label: "Type", style: {}},
            {key: "size", label: "Size", value: sizeStr, style: {"fontFamily": "monospace"}},
            {key: "mode", label: "Mode", style: {"fontFamily": "monospace"}},
            {key: "owner", label: "Owner", style: {}},
            {key: "group", label: "Group", style: {}},
            {key: "modified", label: "Modified", style: {}},
            {key: "accessed", label: "Accessed", style: {}},
            {key: "created", label: "Created", style: {}},
        ];
        for(let i = 0; i < fields.length; i++){
            let f = fields[i];
            let val = f.value !== undefined ? f.value : (data[f.key] !== undefined ? String(data[f.key]) : "");
            if(!val) continue;
            rows.push({
                "Property": {"plaintext": f.label, "cellStyle": {"fontWeight": "bold"}},
                "Value": {"plaintext": val, "copyIcon": true, "cellStyle": f.style},
                "rowStyle": {},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        let title = "File Info";
        if(data.name) title += " \u2014 " + data.name;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
