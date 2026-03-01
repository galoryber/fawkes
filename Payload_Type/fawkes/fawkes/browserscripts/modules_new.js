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
            return {"plaintext": "No modules found"};
        }
        function formatSize(bytes){
            if(bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
            if(bytes >= 1024) return (bytes / 1024).toFixed(1) + " KB";
            return bytes + " B";
        }
        let headers = [
            {"plaintext": "base_addr", "type": "string", "width": 160},
            {"plaintext": "size", "type": "string", "width": 100},
            {"plaintext": "name", "type": "string", "width": 250},
            {"plaintext": "path", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            let lowerName = (e.name || "").toLowerCase();
            if(lowerName === "ntdll.dll" || lowerName === "kernel32.dll" || lowerName === "kernelbase.dll"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            }
            rows.push({
                "base_addr": {"plaintext": e.base_addr || ""},
                "size": {"plaintext": formatSize(e.size || 0)},
                "name": {"plaintext": e.name, "copyIcon": true},
                "path": {"plaintext": e.path || ""},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Loaded Modules (" + data.length + ")",
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
