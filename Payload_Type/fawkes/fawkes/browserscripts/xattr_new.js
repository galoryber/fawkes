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
        let lines = combined.split("\n").filter(l => l.trim());
        // Parse "  name  (N bytes)" lines from list action
        let attrs = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let match = line.match(/^\s+(\S+)\s+\((\d+)\s+bytes?\)/);
            if(match){
                attrs.push({name: match[1], size: match[2]});
            }
        }
        if(attrs.length > 0){
            let headers = [
                {"plaintext": "Attribute", "type": "string", "fillWidth": true},
                {"plaintext": "Size", "type": "string", "width": 100}
            ];
            let rows = [];
            for(let i = 0; i < attrs.length; i++){
                let rowStyle = {};
                if(attrs[i].name.includes("security") || attrs[i].name.includes("selinux")){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                } else if(attrs[i].name.includes("quarantine") || attrs[i].name.includes("com.apple")){
                    rowStyle = {"backgroundColor": "rgba(0,120,255,0.05)"};
                }
                rows.push({
                    "Attribute": {"plaintext": attrs[i].name, "copyIcon": true},
                    "Size": {"plaintext": attrs[i].size + " bytes"},
                    "rowStyle": rowStyle
                });
            }
            return {"table": [{"headers": headers, "rows": rows, "title": "Extended Attributes (" + attrs.length + ")"}]};
        }
        // Fallback for get/set/delete actions
        let rows = [];
        for(let i = 0; i < lines.length; i++){
            let rowStyle = {};
            if(lines[i].includes("[+]")){
                rowStyle = {"backgroundColor": "rgba(0,255,0,0.05)"};
            }
            rows.push({
                "Output": {"plaintext": lines[i]},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{
            "headers": [{"plaintext": "Output", "type": "string", "fillWidth": true}],
            "rows": rows,
            "title": "Extended Attributes"
        }]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
