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
        // Parse HTTP response sections
        let statusMatch = combined.match(/\[\*\] Status: (.+)/);
        let methodMatch = combined.match(/\[\*\] (GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (.+)/);
        let lengthMatch = combined.match(/\[\*\] Content-Length: (\d+)/);

        if(!statusMatch && !methodMatch){
            return {"plaintext": combined};
        }
        let fields = [];
        if(methodMatch){
            fields.push(["Method", methodMatch[1]]);
            fields.push(["URL", methodMatch[2]]);
        }
        if(statusMatch){
            fields.push(["Status", statusMatch[1]]);
        }
        if(lengthMatch){
            let bytes = parseInt(lengthMatch[1]);
            let size = bytes > 1024 ? (bytes / 1024).toFixed(1) + " KB" : bytes + " bytes";
            fields.push(["Content-Length", size]);
        }
        // Extract headers section
        let headersMatch = combined.match(/--- Response Headers ---\n([\s\S]*?)(?=\n--- |$)/);
        if(headersMatch){
            let hLines = headersMatch[1].trim().split("\n");
            for(let h of hLines){
                if(h.includes(":")){
                    let idx = h.indexOf(":");
                    fields.push([h.substring(0, idx).trim(), h.substring(idx + 1).trim()]);
                }
            }
        }
        // Upload summary
        let uploadMatch = combined.match(/--- Upload Summary ---\n([\s\S]*?)$/);
        if(uploadMatch){
            let uLines = uploadMatch[1].trim().split("\n");
            for(let u of uLines){
                if(u.includes(":")){
                    let idx = u.indexOf(":");
                    fields.push([u.substring(0, idx).trim(), u.substring(idx + 1).trim()]);
                }
            }
        }
        let headers = [
            {"plaintext": "Field", "type": "string", "width": 180},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let f of fields){
            let rowStyle = {};
            if(f[0] === "Status"){
                let code = parseInt(f[1]);
                if(code >= 200 && code < 300) rowStyle = {"backgroundColor": "rgba(0,200,0,0.1)"};
                else if(code >= 400) rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
                else if(code >= 300) rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
            }
            rows.push({
                "Field": {"plaintext": f[0]},
                "Value": {"plaintext": f[1], "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        let title = "HTTP Response";
        if(statusMatch) title = "HTTP " + statusMatch[1];
        // Add body as plaintext below the table
        let bodyMatch = combined.match(/--- Response Body ---\n([\s\S]*?)(?=\n--- Upload|$)/);
        let output = {"table": [{"headers": headers, "rows": rows, "title": title}]};
        return output;
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
