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
        // Parse coerce method results: [+] or [-] lines
        let methodLines = combined.match(/\[[+\-]\] .+/g);
        if(!methodLines || methodLines.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Status", "type": "string", "width": 80},
            {"plaintext": "Method", "type": "string", "width": 200},
            {"plaintext": "Details", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let successes = 0;
        for(let line of methodLines){
            let isSuccess = line.startsWith("[+]");
            if(isSuccess) successes++;
            let content = line.replace(/^\[[+\-]\]\s*/, "");
            let parts = content.split(":");
            let method = parts[0].trim();
            let details = parts.length > 1 ? parts.slice(1).join(":").trim() : "";
            rows.push({
                "Status": {"plaintext": isSuccess ? "SUCCESS" : "FAILED"},
                "Method": {"plaintext": method},
                "Details": {"plaintext": details},
                "rowStyle": isSuccess
                    ? {"backgroundColor": "rgba(0,200,0,0.15)"}
                    : {"backgroundColor": "rgba(255,0,0,0.1)"},
            });
        }
        // Extract target info from header lines
        let targetMatch = combined.match(/NTLM coercion against (.+?) /);
        let title = "NTLM Coercion — " + successes + "/" + methodLines.length + " succeeded";
        if(targetMatch) title = "NTLM Coercion: " + targetMatch[1] + " — " + successes + "/" + methodLines.length;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
