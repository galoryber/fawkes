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
        // Detect mode: "LSA Secrets" or "Cached Domain Credentials"
        let isCached = combined.includes("Cached Domain Credentials");
        if(isCached){
            // Parse cached domain credentials (DCC2)
            let entries = [];
            let iterCount = "";
            let i = 0;
            while(i < lines.length){
                let line = lines[i].trim();
                if(line.startsWith("Iteration Count:")){
                    iterCount = line.replace("Iteration Count:", "").trim();
                }
                // [+] DOMAIN\username
                let m = line.match(/^\[\+\]\s+(.+?)\\(.+)$/);
                if(m){
                    let domain = m[1];
                    let username = m[2];
                    let hash = "";
                    if(i + 1 < lines.length){
                        hash = lines[i + 1].trim();
                        i++;
                    }
                    entries.push({domain: domain, username: username, hash: hash});
                }
                i++;
            }
            if(entries.length === 0){
                return {"plaintext": combined};
            }
            let headers = [
                {"plaintext": "Domain", "type": "string", "width": 150},
                {"plaintext": "Username", "type": "string", "width": 180},
                {"plaintext": "DCC2 Hash", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < entries.length; j++){
                let e = entries[j];
                rows.push({
                    "Domain": {"plaintext": e.domain, "copyIcon": true},
                    "Username": {"plaintext": e.username, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                    "DCC2 Hash": {"plaintext": e.hash, "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}},
                    "rowStyle": {"backgroundColor": "rgba(0,200,0,0.12)"},
                });
            }
            let title = "Cached Domain Credentials \u2014 " + entries.length + " hashes";
            if(iterCount) title += " (iterations: " + iterCount + ")";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        // Parse LSA secrets dump
        let secrets = [];
        let i = 0;
        while(i < lines.length){
            let line = lines[i].trim();
            // [+] SecretName:  or  [!] SecretName: decrypt failed
            let mOk = line.match(/^\[\+\]\s+(.+?):$/);
            let mFail = line.match(/^\[!\]\s+(.+?):\s+decrypt failed/);
            if(mOk){
                let name = mOk[1];
                let value = "";
                i++;
                // Collect indented value lines
                while(i < lines.length && lines[i].match(/^\s/) && !lines[i].trim().startsWith("[") && lines[i].trim().length > 0){
                    if(value) value += "\n";
                    value += lines[i].trim();
                    i++;
                }
                secrets.push({name: name, value: value, status: "decrypted"});
                continue;
            } else if(mFail){
                secrets.push({name: mFail[1], value: "decrypt failed", status: "failed"});
            }
            i++;
        }
        if(secrets.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Secret Name", "type": "string", "width": 220},
            {"plaintext": "Status", "type": "string", "width": 90},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let decrypted = 0;
        for(let j = 0; j < secrets.length; j++){
            let s = secrets[j];
            let isOk = s.status === "decrypted";
            if(isOk) decrypted++;
            let isSvc = s.name.startsWith("_SC_");
            let isDpapi = s.name.includes("DPAPI");
            let isPwd = s.name.toLowerCase().includes("password");
            let bg = isOk ? "rgba(0,200,0,0.08)" : "rgba(255,0,0,0.08)";
            if(isPwd && isOk) bg = "rgba(0,200,0,0.18)";
            rows.push({
                "Secret Name": {"plaintext": s.name, "copyIcon": true, "cellStyle": isSvc ? {} : {"fontWeight": "bold"}},
                "Status": {"plaintext": isOk ? "\u2713" : "\u2717", "cellStyle": {"color": isOk ? "green" : "red", "textAlign": "center"}},
                "Value": {"plaintext": s.value, "copyIcon": isOk, "cellStyle": {"fontFamily": "monospace"}},
                "rowStyle": {"backgroundColor": bg},
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "LSA Secrets \u2014 " + secrets.length + " secrets (" + decrypted + " decrypted)",
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
