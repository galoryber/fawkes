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
        let lines = combined.split("\n");
        // Parse [+] account blocks
        let accounts = [];
        let current = null;
        let summaryLine = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(line.startsWith("[+] ")){
                if(current) accounts.push(current);
                // Parse: [+] Username (RID: 500)
                let match = line.match(/\[\+\]\s+(.+?)\s+\(RID:\s*(\d+)\)/);
                current = {
                    username: match ? match[1] : line.substring(4),
                    rid: match ? match[2] : "",
                    ntlm: "", lm: "", aes256: "", aes128: "", hash: "",
                };
            } else if(current){
                if(line.startsWith("NTLM:")){
                    current.ntlm = line.substring(5).trim();
                } else if(line.startsWith("LM:")){
                    current.lm = line.substring(3).trim();
                } else if(line.startsWith("AES256:")){
                    current.aes256 = line.substring(7).trim();
                } else if(line.startsWith("AES128:")){
                    current.aes128 = line.substring(7).trim();
                } else if(line.startsWith("Hash:")){
                    current.hash = line.substring(5).trim();
                }
            }
            if(line.startsWith("[*]") && line.includes("dumped")){
                summaryLine = line;
            }
        }
        if(current) accounts.push(current);
        if(accounts.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Username", "type": "string", "width": 180},
            {"plaintext": "RID", "type": "number", "width": 70},
            {"plaintext": "NTLM", "type": "string", "fillWidth": true},
            {"plaintext": "AES256", "type": "string", "fillWidth": true},
            {"plaintext": "Hash Line", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < accounts.length; j++){
            let a = accounts[j];
            let rowStyle = {"backgroundColor": "rgba(0,200,0,0.12)"};
            rows.push({
                "Username": {"plaintext": a.username, "copyIcon": true},
                "RID": {"plaintext": a.rid},
                "NTLM": {"plaintext": a.ntlm, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                "AES256": {"plaintext": a.aes256 || "\u2014", "copyIcon": a.aes256 ? true : false},
                "Hash Line": {"plaintext": a.hash ? a.hash.substring(0, 50) + "..." : "\u2014", "copyIcon": a.hash ? true : false},
                "rowStyle": rowStyle,
            });
        }
        let title = "DCSync \u2014 " + accounts.length + " accounts extracted";
        if(summaryLine) title += " (" + summaryLine.replace("[*] ", "") + ")";
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
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
