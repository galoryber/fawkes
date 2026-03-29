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
        // Known suspicious/interesting pipe names for highlighting
        let suspiciousPipes = new Set([
            "msagent_", "MSSE-", "postex_", "status_", "mojo_", "lsarpc",
            "epmapper", "samr", "netlogon", "svcctl", "winreg", "atsvc",
        ]);
        let c2Pipes = new Set([
            "msagent_", "MSSE-", "postex_", "status_", "interprocess_",
        ]);
        let headers = [
            {"plaintext": "#", "type": "number", "width": 60},
            {"plaintext": "Pipe Name", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let idx = 0;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            // Parse pipe lines: \\.\pipe\<name>
            let pipeMatch = line.match(/^\\\\\.\\pipe\\(.+)/);
            if(!pipeMatch) continue;
            let pipeName = pipeMatch[1];
            idx++;
            let rowStyle = {};
            // Highlight known C2/implant pipe patterns
            for(let prefix of c2Pipes){
                if(pipeName.startsWith(prefix) || pipeName.includes(prefix)){
                    rowStyle = {"backgroundColor": "rgba(244,67,54,0.15)"};
                    break;
                }
            }
            // Highlight RPC pipes in blue
            if(!rowStyle.backgroundColor){
                for(let rpc of suspiciousPipes){
                    if(pipeName === rpc || pipeName.startsWith(rpc)){
                        rowStyle = {"backgroundColor": "rgba(33,150,243,0.1)"};
                        break;
                    }
                }
            }
            rows.push({
                "#": {"plaintext": String(idx)},
                "Pipe Name": {"plaintext": pipeName, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        let title = "Named Pipes \u2014 " + rows.length;
        let filterMatch = combined.match(/Filter:\s+(.+)/);
        if(filterMatch){
            title += " (filter: " + filterMatch[1].trim() + ")";
        }
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
