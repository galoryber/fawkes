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
            return {"plaintext": "No prefetch files found"};
        }
        function formatSize(bytes){
            if(bytes === 0) return "0 B";
            let units = ["B", "KB", "MB"];
            let i = 0;
            let size = bytes;
            while(size >= 1024 && i < units.length - 1){
                size /= 1024;
                i++;
            }
            return size.toFixed(i === 0 ? 0 : 1) + " " + units[i];
        }
        let headers = [
            {"plaintext": "executable", "type": "string", "fillWidth": true},
            {"plaintext": "runs", "type": "number", "width": 80},
            {"plaintext": "last_run", "type": "string", "width": 180},
            {"plaintext": "size", "type": "string", "width": 90},
            {"plaintext": "hash", "type": "string", "width": 100},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            let exeLower = (e.executable || "").toLowerCase();
            if(exeLower.includes("powershell") || exeLower.includes("cmd.exe") || exeLower.includes("wscript") || exeLower.includes("cscript") || exeLower.includes("mshta")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            }
            rows.push({
                "executable": {"plaintext": e.executable, "copyIcon": true},
                "runs": {"plaintext": String(e.run_count || 0)},
                "last_run": {"plaintext": e.last_run || "-"},
                "size": {"plaintext": formatSize(e.file_size)},
                "hash": {"plaintext": e.hash || "-"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Prefetch Files (" + data.length + ")",
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
