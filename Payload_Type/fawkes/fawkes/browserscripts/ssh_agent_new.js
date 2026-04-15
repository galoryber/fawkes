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
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No SSH keys found in agent"};
        }
        let headers = [
            {"plaintext": "Fingerprint", "type": "string", "fillWidth": true},
            {"plaintext": "Type", "type": "string", "width": 120},
            {"plaintext": "Comment", "type": "string", "width": 200},
            {"plaintext": "Bits", "type": "number", "width": 80},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let typeStyle = {};
            let t = (e.type || "").toLowerCase();
            if(t.includes("rsa") && e.bits && e.bits < 2048){
                typeStyle = {"color": "#ff8c00", "fontWeight": "bold"};
            } else if(t.includes("ed25519")){
                typeStyle = {"color": "#4caf50"};
            }
            rows.push({
                "Fingerprint": {
                    "plaintext": e.fingerprint || "",
                    "copyIcon": true,
                    "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"},
                },
                "Type": {"plaintext": e.type || "", "cellStyle": typeStyle},
                "Comment": {"plaintext": e.comment || "", "copyIcon": true},
                "Bits": {"plaintext": String(e.bits || "")},
                "rowStyle": {},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "SSH Agent Keys (" + data.length + " loaded)",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
