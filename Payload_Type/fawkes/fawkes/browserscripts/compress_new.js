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
        if(typeof data !== "object" || data === null){
            return {"plaintext": combined};
        }
        // stage, exfil, or stage-exfil metadata
        let headers = [];
        let rows = [];
        if(data.staging_dir !== undefined || data.archive_path !== undefined){
            // Stage or stage-exfil result
            let fields = [];
            if(data.source_path) fields.push(["Source", data.source_path]);
            if(data.staging_dir) fields.push(["Staging Dir", data.staging_dir]);
            if(data.archive_path) fields.push(["Archive", data.archive_path]);
            if(data.file_count !== undefined) fields.push(["Files", String(data.file_count)]);
            if(data.original_size !== undefined) fields.push(["Original Size", (data.original_size / 1024).toFixed(1) + " KB"]);
            if(data.archive_size !== undefined) fields.push(["Archive Size", (data.archive_size / 1024).toFixed(1) + " KB"]);
            if(data.encryption_key) fields.push(["Encryption Key", data.encryption_key]);
            if(data.sha256 || data.source_sha256) fields.push(["SHA-256", data.sha256 || data.source_sha256]);
            if(data.archive_sha256) fields.push(["Archive SHA-256", data.archive_sha256]);
            if(data.status) fields.push(["Status", data.status]);
            if(data.cleaned_up !== undefined) fields.push(["Cleaned Up", data.cleaned_up ? "Yes" : "No"]);
            if(data.file_size !== undefined) fields.push(["File Size", (data.file_size / 1024).toFixed(1) + " KB"]);
            headers = [
                {"plaintext": "field", "type": "string", "width": 140},
                {"plaintext": "value", "type": "string", "fillWidth": true},
            ];
            for(let f of fields){
                let style = {};
                if(f[0] === "Encryption Key") style = {"backgroundColor": "rgba(255,0,0,0.1)"};
                if(f[0] === "Status" && f[1] === "success") style = {"backgroundColor": "rgba(0,200,0,0.1)"};
                rows.push({
                    "field": {"plaintext": f[0]},
                    "value": {"plaintext": f[1], "copyIcon": true},
                    "rowStyle": style,
                });
            }
            let title = "Data Staging";
            if(data.status) title = "Exfiltration — " + data.status;
            if(data.archive_sha256) title = "Stage + Exfil";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        return {"plaintext": combined};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
