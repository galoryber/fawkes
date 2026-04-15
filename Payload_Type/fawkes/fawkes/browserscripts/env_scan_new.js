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
            return {"plaintext": "No environment variables found"};
        }
        let securityVars = [
            "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH", "PYTHONPATH", "CLASSPATH", "NODE_PATH",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "GCP_SERVICE_ACCOUNT",
            "HISTFILE", "HISTSIZE", "HISTCONTROL",
        ];
        let securityPatterns = /^(.*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|AUTH|API_KEY|AWS_|PRIVATE|PROXY).*)$/i;
        let headers = [
            {"plaintext": "Variable Name", "type": "string", "width": 250},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
            {"plaintext": "Category", "type": "string", "width": 140},
        ];
        let rows = [];
        let secCount = 0;
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let name = e.name || "";
            let value = e.value || "";
            let category = e.category || "";
            // Truncate value to 100 chars
            let displayValue = value.length > 100 ? value.substring(0, 100) + "\u2026" : value;
            // Check if security-relevant
            let isSecurity = securityVars.indexOf(name) !== -1 || securityPatterns.test(name);
            if(isSecurity) secCount++;
            let rowStyle = isSecurity
                ? {"backgroundColor": "rgba(255,235,59,0.15)"}
                : {};
            let nameStyle = isSecurity
                ? {"fontWeight": "bold", "color": "#d4a017"}
                : {"fontWeight": "bold"};
            rows.push({
                "Variable Name": {
                    "plaintext": name,
                    "copyIcon": true,
                    "cellStyle": nameStyle,
                },
                "Value": {
                    "plaintext": displayValue,
                    "copyIcon": true,
                    "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em", "whiteSpace": "pre-wrap"},
                },
                "Category": {"plaintext": category},
                "rowStyle": rowStyle,
            });
        }
        let title = "Environment Scan \u2014 " + data.length + " variables";
        if(secCount > 0) title += " (" + secCount + " security-relevant)";
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
