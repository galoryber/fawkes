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

        let pidMatch = combined.match(/PID\s+(\d+)/);
        let patternMatch = combined.match(/Pattern:\s+(.+?)(?:\s+\(|$)/m);
        let regionsMatch = combined.match(/Regions scanned:\s+(\d+)/);
        let bytesMatch = combined.match(/Bytes scanned:\s+(\S+)/);
        let matchesMatch = combined.match(/Matches found:\s+(\d+)/);
        let matchCount = matchesMatch ? parseInt(matchesMatch[1]) : 0;

        let headers = [
            {"plaintext": "Property", "type": "string", "width": 140},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let hasMatches = matchCount > 0;
        let rows = [
            {"Property": {"plaintext": "Operation"}, "Value": {"plaintext": "Memory Scan", "cellStyle": {"fontWeight": "bold"}}, "rowStyle": {}},
            {"Property": {"plaintext": "Matches"}, "Value": {"plaintext": matchCount.toString(), "cellStyle": {"fontWeight": "bold", "color": hasMatches ? "#4CAF50" : "#FF9800"}}, "rowStyle": {"backgroundColor": hasMatches ? "rgba(76,175,80,0.1)" : ""}},
        ];
        if(pidMatch) rows.push({"Property": {"plaintext": "Target PID"}, "Value": {"plaintext": pidMatch[1], "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(patternMatch) rows.push({"Property": {"plaintext": "Pattern"}, "Value": {"plaintext": patternMatch[1].trim(), "copyIcon": true, "cellStyle": {"fontFamily": "monospace"}}, "rowStyle": {}});
        if(regionsMatch) rows.push({"Property": {"plaintext": "Regions Scanned"}, "Value": {"plaintext": regionsMatch[1]}, "rowStyle": {}});
        if(bytesMatch) rows.push({"Property": {"plaintext": "Bytes Scanned"}, "Value": {"plaintext": bytesMatch[1]}, "rowStyle": {}});

        // Parse individual match addresses
        let matchLines = combined.match(/Match \d+: (0x[0-9A-Fa-f]+)/g);
        if(matchLines && matchLines.length > 0){
            let addrs = matchLines.map(function(m){ return m.replace(/Match \d+: /, ""); }).join(", ");
            rows.push({"Property": {"plaintext": "Match Addresses"}, "Value": {"plaintext": addrs, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}, "rowStyle": {}});
        }

        return {"table": [{"headers": headers, "rows": rows, "title": "Memory Scan Results"}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
