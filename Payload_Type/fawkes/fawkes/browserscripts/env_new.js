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
        let lines = combined.split("\n").filter(l => l.trim().length > 0);
        // Check if this is a list output (VAR=VALUE format)
        let envVars = [];
        let sensitivePatterns = /^(.*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|AUTH|API_KEY|AWS_|PRIVATE).*)$/i;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let eqIdx = line.indexOf("=");
            if(eqIdx > 0){
                let name = line.substring(0, eqIdx);
                let value = line.substring(eqIdx + 1);
                // Validate it looks like an env var name (no spaces before =)
                if(!name.includes(" ") || name.startsWith("  ")){
                    envVars.push({name: name.trim(), value: value});
                }
            }
        }
        if(envVars.length < 2){
            // Not a list output (set/unset/get result) — show as plaintext
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Variable", "type": "string", "width": 250},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let sensitiveCount = 0;
        for(let j = 0; j < envVars.length; j++){
            let e = envVars[j];
            let isSensitive = sensitivePatterns.test(e.name);
            if(isSensitive) sensitiveCount++;
            let isPath = e.name === "PATH" || e.name === "LD_LIBRARY_PATH" || e.name === "PYTHONPATH";
            let bg = isSensitive ? "rgba(255,165,0,0.15)" : "transparent";
            rows.push({
                "Variable": {
                    "plaintext": e.name,
                    "copyIcon": true,
                    "cellStyle": isSensitive ? {"fontWeight": "bold", "color": "#d94f00"} : {"fontWeight": "bold"},
                },
                "Value": {
                    "plaintext": isPath ? e.value.replace(/:/g, "\n") : e.value,
                    "copyIcon": true,
                    "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em", "whiteSpace": "pre-wrap"},
                },
                "rowStyle": {"backgroundColor": bg},
            });
        }
        let title = "Environment Variables \u2014 " + envVars.length + " vars";
        if(sensitiveCount > 0) title += " (" + sensitiveCount + " potentially sensitive)";
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
