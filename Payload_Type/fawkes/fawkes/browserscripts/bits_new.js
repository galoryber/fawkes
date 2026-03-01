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
            return {"plaintext": "No BITS jobs found"};
        }
        function formatBytes(b){
            if(b >= 1073741824) return (b/1073741824).toFixed(1) + " GB";
            if(b >= 1048576) return (b/1048576).toFixed(1) + " MB";
            if(b >= 1024) return (b/1024).toFixed(1) + " KB";
            return b + " B";
        }
        let stateColors = {
            "Transferring": "rgba(0,200,0,0.15)",
            "Suspended": "rgba(255,165,0,0.12)",
            "Error": "rgba(255,0,0,0.15)",
            "TransientError": "rgba(255,0,0,0.1)",
            "Transferred": "rgba(100,149,237,0.12)",
        };
        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "state", "type": "string", "width": 100},
            {"plaintext": "progress", "type": "string", "width": 120},
            {"plaintext": "files", "type": "string", "width": 70},
            {"plaintext": "job_id", "type": "string", "width": 300},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(stateColors[e.state]){
                rowStyle = {"backgroundColor": stateColors[e.state]};
            }
            let progress = "0 B";
            if(e.bytes_total > 0 && e.bytes_total !== 0xFFFFFFFFFFFFFFFF){
                let pct = (e.bytes_transferred / e.bytes_total * 100).toFixed(0);
                progress = pct + "% (" + formatBytes(e.bytes_transferred) + ")";
            } else if(e.bytes_transferred > 0){
                progress = formatBytes(e.bytes_transferred);
            }
            rows.push({
                "name": {"plaintext": e.name},
                "state": {"plaintext": e.state},
                "progress": {"plaintext": progress},
                "files": {"plaintext": e.files_transferred + "/" + e.files_total},
                "job_id": {"plaintext": e.job_id, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "BITS Jobs — " + data.length + " job(s)",
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
