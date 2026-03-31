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

        // Detect action by output header
        if(combined.startsWith("WMI Process Create")){
            // Execute action: WMI Process Create on <host>:\n  Command: ...\n  Return Value: ...
            let hostMatch = combined.match(/WMI Process Create on (.+?):/);
            let cmdMatch = combined.match(/Command:\s+(.+)/);
            let retMatch = combined.match(/Return Value:\s+(\d+)/);
            let host = hostMatch ? hostMatch[1] : "unknown";
            let command = cmdMatch ? cmdMatch[1].trim() : "";
            let retVal = retMatch ? retMatch[1] : "?";

            let headers = [
                {"plaintext": "Property", "type": "string", "width": 130},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let retStyle = {};
            if(retVal === "0"){
                retStyle = {"backgroundColor": "rgba(76,175,80,0.1)"};
            } else {
                retStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
            }
            let retLabels = {"0": "Success", "2": "Access Denied", "3": "Insufficient Privilege", "8": "Unknown Failure", "21": "Invalid Parameter"};
            let retLabel = retLabels[retVal] || "Error " + retVal;

            let rows = [
                {"Property": {"plaintext": "Target"}, "Value": {"plaintext": host, "copyIcon": true}, "rowStyle": {}},
                {"Property": {"plaintext": "Command"}, "Value": {"plaintext": command, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}}, "rowStyle": {}},
                {"Property": {"plaintext": "Return Value"}, "Value": {"plaintext": retVal + " (" + retLabel + ")"}, "rowStyle": retStyle},
            ];
            return {"table": [{"headers": headers, "rows": rows, "title": "WMI Process Create: " + host}]};

        } else if(combined.startsWith("WMI Query Result") || combined.startsWith("WMI Process List") || combined.startsWith("WMI OS Info")){
            // Query/Process List/OS Info: property=value format, items separated by ---
            let titleLine = combined.split("\n")[0];
            let bodyStart = combined.indexOf("\n");
            let body = bodyStart >= 0 ? combined.substring(bodyStart + 1).trim() : "";

            if(!body || body === "(no results)"){
                return {"plaintext": combined};
            }

            // Split items by ---
            let items = body.split(/\n---\n/);

            if(items.length === 1 && !body.includes("=")){
                return {"plaintext": combined};
            }

            // Parse property=value pairs from first item to get column names
            let allKeys = [];
            let allRows = [];
            for(let i = 0; i < items.length; i++){
                let lines = items[i].trim().split("\n");
                let row = {};
                for(let l = 0; l < lines.length; l++){
                    let eqIdx = lines[l].indexOf("=");
                    if(eqIdx < 0) continue;
                    let key = lines[l].substring(0, eqIdx).trim();
                    let val = lines[l].substring(eqIdx + 1).trim();
                    row[key] = val;
                    if(allKeys.indexOf(key) < 0) allKeys.push(key);
                }
                if(Object.keys(row).length > 0) allRows.push(row);
            }

            if(allKeys.length === 0){
                return {"plaintext": combined};
            }

            let headers = [];
            for(let k = 0; k < allKeys.length; k++){
                let width = allKeys[k].length < 15 ? 120 : undefined;
                let h = {"plaintext": allKeys[k], "type": "string"};
                if(width) h.width = width; else h.fillWidth = true;
                headers.push(h);
            }

            let rows = [];
            for(let r = 0; r < allRows.length; r++){
                let rowData = {};
                for(let k = 0; k < allKeys.length; k++){
                    let key = allKeys[k];
                    rowData[key] = {"plaintext": allRows[r][key] || "", "copyIcon": true};
                }
                rowData["rowStyle"] = {};
                rows.push(rowData);
            }

            let title = titleLine.replace(":", "") + " (" + allRows.length + " items)";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }

        return {"plaintext": combined};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
