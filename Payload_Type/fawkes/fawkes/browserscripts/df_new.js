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
            return {"plaintext": "No filesystems found"};
        }
        function formatSize(bytes){
            if(bytes === 0) return "0 B";
            let units = ["B", "KB", "MB", "GB", "TB"];
            let i = 0;
            let size = bytes;
            while(size >= 1024 && i < units.length - 1){
                size /= 1024;
                i++;
            }
            return size.toFixed(i === 0 ? 0 : 1) + " " + units[i];
        }
        let headers = [
            {"plaintext": "filesystem", "type": "string", "fillWidth": true},
            {"plaintext": "total", "type": "string", "width": 100},
            {"plaintext": "used", "type": "string", "width": 100},
            {"plaintext": "available", "type": "string", "width": 100},
            {"plaintext": "use%", "type": "number", "width": 70},
            {"plaintext": "mount_point", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.use_percent >= 90){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            } else if(e.use_percent >= 75){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            }
            rows.push({
                "filesystem": {"plaintext": e.filesystem},
                "total": {"plaintext": formatSize(e.total_bytes)},
                "used": {"plaintext": formatSize(e.used_bytes)},
                "available": {"plaintext": formatSize(e.avail_bytes)},
                "use%": {"plaintext": e.use_percent + "%"},
                "mount_point": {"plaintext": e.mount_point, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Disk Usage (" + data.length + " filesystems)",
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
