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
        // Parse keychain item entries from dump output
        // Format: keychain: "path"\nclass: 0x000000XX\nattributes:\n    "key"<type>="value"\n
        let items = combined.split(/keychain: "/);
        if(items.length <= 1){
            // Try find-password/find-internet single result
            let passwordMatch = combined.match(/password: "(.+?)"/);
            if(passwordMatch){
                let fields = [];
                let patterns = [
                    ["Service", /svce"<blob>="(.+?)"/],
                    ["Account", /acct"<blob>="(.+?)"/],
                    ["Server", /srvr"<blob>="(.+?)"/],
                    ["Protocol", /ptcl"<uint32>="(.+?)"/],
                    ["Label", /labl"<blob>="(.+?)"/],
                    ["Password", /password: "(.+?)"/],
                ];
                for(let p of patterns){
                    let m = combined.match(p[1]);
                    if(m) fields.push([p[0], m[1]]);
                }
                if(fields.length === 0) return {"plaintext": combined};
                let headers = [
                    {"plaintext": "Field", "type": "string", "width": 120},
                    {"plaintext": "Value", "type": "string", "fillWidth": true},
                ];
                let rows = fields.map(function(f){
                    let rowStyle = {};
                    if(f[0] === "Password") rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                    return {
                        "Field": {"plaintext": f[0]},
                        "Value": {"plaintext": f[1], "copyIcon": true},
                        "rowStyle": rowStyle,
                    };
                });
                return {"table": [{"headers": headers, "rows": rows, "title": "Keychain Item"}]};
            }
            return {"plaintext": combined};
        }
        // Parse dump: extract service/account/server from each entry
        let headers = [
            {"plaintext": "Keychain", "type": "string", "width": 200},
            {"plaintext": "Class", "type": "string", "width": 80},
            {"plaintext": "Service/Server", "type": "string", "fillWidth": true},
            {"plaintext": "Account", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let i = 1; i < items.length; i++){
            let item = items[i];
            let keychain = item.split('"')[0] || "";
            let classMatch = item.match(/class: "?(\w+)/);
            let svcMatch = item.match(/svce"<blob>="(.+?)"/);
            let srvMatch = item.match(/srvr"<blob>="(.+?)"/);
            let acctMatch = item.match(/acct"<blob>="(.+?)"/);
            rows.push({
                "Keychain": {"plaintext": keychain},
                "Class": {"plaintext": classMatch ? classMatch[1] : ""},
                "Service/Server": {"plaintext": (svcMatch ? svcMatch[1] : "") || (srvMatch ? srvMatch[1] : ""), "copyIcon": true},
                "Account": {"plaintext": acctMatch ? acctMatch[1] : "", "copyIcon": true},
                "rowStyle": {},
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Keychain Dump (" + rows.length + " items)"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
