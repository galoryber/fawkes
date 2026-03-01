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
            return {"plaintext": "No Shimcache entries found"};
        }
        let headers = [
            {"plaintext": "#", "type": "number", "width": 60},
            {"plaintext": "last_modified", "type": "string", "width": 180},
            {"plaintext": "path", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            let pathLower = (e.path || "").toLowerCase();
            if(pathLower.includes("powershell") || pathLower.includes("cmd.exe") || pathLower.includes("wscript") || pathLower.includes("cscript") || pathLower.includes("mshta")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            }
            rows.push({
                "#": {"plaintext": String(e.index)},
                "last_modified": {"plaintext": e.last_modified || "-"},
                "path": {"plaintext": e.path, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Shimcache (" + data.length + " entries)",
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
