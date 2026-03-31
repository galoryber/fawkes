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
        // Parse: DCOM <ObjectType> executed on <host>:
        let headerMatch = combined.match(/DCOM\s+(\S+)\s+executed on\s+(\S+?):/);
        if(!headerMatch){
            return {"plaintext": combined};
        }
        let objectType = headerMatch[1];
        let host = headerMatch[2];

        // Parse key: value fields
        let cmdMatch = combined.match(/Command:\s+(.+)/);
        let argsMatch = combined.match(/Args:\s+(.*)/);
        let dirMatch = combined.match(/Directory:\s+(.*)/);
        let methodMatch = combined.match(/Method:\s+(.+)/);
        let authMatch = combined.match(/Auth:\s+(.+)/);

        let headers = [
            {"plaintext": "Property", "type": "string", "width": 120},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [
            {"Property": {"plaintext": "Target"}, "Value": {"plaintext": host, "copyIcon": true}, "rowStyle": {}},
            {"Property": {"plaintext": "DCOM Object"}, "Value": {"plaintext": objectType, "cellStyle": {"fontWeight": "bold"}}, "rowStyle": {}},
        ];
        if(methodMatch){
            rows.push({"Property": {"plaintext": "Method"}, "Value": {"plaintext": methodMatch[1].trim(), "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}, "rowStyle": {}});
        }
        if(cmdMatch){
            rows.push({"Property": {"plaintext": "Command"}, "Value": {"plaintext": cmdMatch[1].trim(), "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}, "rowStyle": {}});
        }
        if(argsMatch && argsMatch[1].trim()){
            rows.push({"Property": {"plaintext": "Arguments"}, "Value": {"plaintext": argsMatch[1].trim(), "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}, "rowStyle": {}});
        }
        if(dirMatch && dirMatch[1].trim()){
            rows.push({"Property": {"plaintext": "Directory"}, "Value": {"plaintext": dirMatch[1].trim()}, "rowStyle": {}});
        }
        if(authMatch){
            rows.push({"Property": {"plaintext": "Auth"}, "Value": {"plaintext": authMatch[1].trim()}, "rowStyle": {"backgroundColor": "rgba(255,165,0,0.1)"}});
        }

        let title = "DCOM Execution: " + objectType + " on " + host;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
