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
        let lines = combined.trim().split("\n").filter(l => l.trim().length > 0);
        if(lines.length === 0){
            return {"plaintext": "No hashes found"};
        }
        // Check if first line looks like a hash entry (user:rid:lm:nt:::)
        let firstParts = lines[0].split(":");
        if(firstParts.length < 4){
            return {"plaintext": combined};
        }
        let emptyNT = "31d6cfe0d16ae931b73c59d7e0c089c0";
        let emptyLM = "aad3b435b51404eeaad3b435b51404ee";
        let headers = [
            {"plaintext": "Username", "type": "string", "width": 180},
            {"plaintext": "RID", "type": "number", "width": 70},
            {"plaintext": "NT Hash", "type": "string", "fillWidth": true},
            {"plaintext": "LM Hash", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let crackable = 0;
        for(let j = 0; j < lines.length; j++){
            let parts = lines[j].split(":");
            if(parts.length < 4) continue;
            let username = parts[0];
            let rid = parts[1];
            let lm = parts[2];
            let nt = parts[3];
            let isEmpty = (nt === emptyNT);
            if(!isEmpty) crackable++;
            let rowStyle = {};
            if(isEmpty){
                rowStyle = {"backgroundColor": "rgba(128,128,128,0.1)"};
            } else {
                rowStyle = {"backgroundColor": "rgba(0,200,0,0.12)"};
            }
            rows.push({
                "Username": {"plaintext": username, "copyIcon": true},
                "RID": {"plaintext": rid},
                "NT Hash": {
                    "plaintext": nt,
                    "copyIcon": true,
                    "cellStyle": isEmpty ? {"color": "#888"} : {"fontWeight": "bold"},
                },
                "LM Hash": {
                    "plaintext": lm,
                    "copyIcon": lm !== emptyLM,
                    "cellStyle": lm === emptyLM ? {"color": "#888"} : {},
                },
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Hashdump \u2014 " + rows.length + " accounts (" + crackable + " with non-empty NT hash)",
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
