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
        combined = combined.trim();

        let sizeMatch = combined.match(/(\d+)\s*bytes/);
        let success = combined.includes("successfully") || combined.includes("[+]");
        let failed = combined.includes("failed") || combined.includes("Error:");
        let dotnetMatch = combined.match(/\.NET assembly/i);
        let timeoutMatch = combined.match(/timed out after (\d+)s/);

        let headers = [
            {"plaintext": "Property", "type": "string", "width": 140},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let status = failed ? "FAILED" : (success ? "SUCCESS" : "RUNNING");
        let statusColor = failed ? "#f44336" : (success ? "#4CAF50" : "#FF9800");
        let statusBg = failed ? "rgba(244,67,54,0.1)" : (success ? "rgba(76,175,80,0.1)" : "rgba(255,152,0,0.1)");
        let rows = [
            {"Property": {"plaintext": "Technique"}, "Value": {"plaintext": "Inline Assembly", "cellStyle": {"fontWeight": "bold"}}, "rowStyle": {}},
            {"Property": {"plaintext": "Status"}, "Value": {"plaintext": status, "cellStyle": {"fontWeight": "bold", "color": statusColor}}, "rowStyle": {"backgroundColor": statusBg}},
        ];
        if(sizeMatch) rows.push({"Property": {"plaintext": "Payload Size"}, "Value": {"plaintext": sizeMatch[1] + " bytes"}, "rowStyle": {}});
        if(dotnetMatch) rows.push({"Property": {"plaintext": "Type"}, "Value": {"plaintext": ".NET Assembly", "cellStyle": {"color": "#2196F3"}}, "rowStyle": {}});
        if(timeoutMatch) rows.push({"Property": {"plaintext": "Timeout"}, "Value": {"plaintext": timeoutMatch[1] + "s", "cellStyle": {"color": "#FF9800"}}, "rowStyle": {}});

        // Extract stdout output (everything after the status lines)
        let lines = combined.split("\n");
        let outputLines = [];
        let pastHeader = false;
        for(let i = 0; i < lines.length; i++){
            if(pastHeader){
                outputLines.push(lines[i]);
            } else if(lines[i].match(/^\[\+\]/) || lines[i].match(/^\[!\]/)){
                pastHeader = true;
                // Check if there's content after this line
            }
        }
        let execOutput = outputLines.join("\n").trim();
        if(execOutput){
            rows.push({"Property": {"plaintext": "Output"}, "Value": {"plaintext": execOutput, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em", "whiteSpace": "pre-wrap"}}, "rowStyle": {}});
        }

        return {"table": [{"headers": headers, "rows": rows, "title": "Assembly execution"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
