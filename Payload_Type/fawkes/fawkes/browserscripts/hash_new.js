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
            {"plaintext": "Algorithm", "type": "string", "width": 100},
            {"plaintext": "Hash", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let algos = ["md5", "sha1", "sha256", "sha512"];
        for(let i = 0; i < algos.length; i++){
            let a = algos[i];
            if(data[a]){
                rows.push({
                    "Algorithm": {"plaintext": a.toUpperCase(), "cellStyle": {"fontWeight": "bold"}},
                    "Hash": {"plaintext": data[a], "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                });
            }
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        let title = "File Hashes";
        if(data.file) title += " \u2014 " + data.file;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
