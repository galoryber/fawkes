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
        if(timeoutMatch) rows.push({"Property": {"plaintext": "Timeout"}, "Value": {"plaintext": timeoutMatch[1] + "s", "cellStyle": {"color": "#FF9800"}}, "rowStyle": {}});

        // Extract STDOUT and STDERR sections
        let stdoutContent = "";
        let stderrContent = "";
        let stdoutIdx = combined.indexOf("=== STDOUT ===");
        let stderrIdx = combined.indexOf("=== STDERR ===");

        if(stdoutIdx >= 0){
            let start = combined.indexOf("\n", stdoutIdx) + 1;
            let end = stderrIdx >= 0 ? stderrIdx : combined.length;
            stdoutContent = combined.substring(start, end).trim();
        }
        if(stderrIdx >= 0){
            let start = combined.indexOf("\n", stderrIdx) + 1;
            stderrContent = combined.substring(start).trim();
        }

        // Build plaintext output with assembly output prominently displayed
        let output = "";
        if(stdoutContent){
            output += stdoutContent;
        }
        if(stderrContent){
            if(output) output += "\n\n--- STDERR ---\n";
            output += stderrContent;
        }

        // If no STDOUT/STDERR markers found, extract everything after status lines
        if(!output){
            let lines = combined.split("\n");
            let outputLines = [];
            let foundEnd = false;
            for(let i = 0; i < lines.length; i++){
                if(foundEnd){
                    outputLines.push(lines[i]);
                } else if(lines[i].match(/Assembly executed/) || lines[i].match(/Assembly invocation/)){
                    foundEnd = true;
                }
            }
            output = outputLines.join("\n").trim();
        }

        if(output){
            return {
                "table": [{"headers": headers, "rows": rows, "title": "Assembly Execution"}],
                "plaintext": output
            };
        }

        return {"table": [{"headers": headers, "rows": rows, "title": "Assembly Execution"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
