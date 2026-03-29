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
        let tables = [];
        // Detect section type
        let hasMasterKeys = combined.includes("MASTER KEYS");
        let hasChromeKey = combined.includes("CHROME/EDGE");
        let hasDecrypt = combined.includes("DECRYPTION RESULT");
        // Parse master keys
        if(hasMasterKeys){
            let entries = [];
            let currentSID = "";
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed === "" || trimmed.startsWith("===")) continue;
                // SID directory: "--- /path/to/SID ---"
                let sidMatch = trimmed.match(/^---\s+(.+?)\s+---/);
                if(sidMatch){
                    currentSID = sidMatch[1];
                    continue;
                }
                // Key entry: "[KEY]      guid  (size bytes, modified timestamp)"
                let keyMatch = trimmed.match(/^\[(\w+)\]\s+(\S+)\s+\((.+)\)/);
                if(keyMatch && currentSID){
                    entries.push({sid: currentSID, type: keyMatch[1], guid: keyMatch[2], details: keyMatch[3]});
                }
                // Total line
                if(trimmed.startsWith("--- Total:")) continue;
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Type", "type": "string", "width": 100},
                    {"plaintext": "GUID / Name", "type": "string", "width": 300},
                    {"plaintext": "Details", "type": "string", "width": 250},
                    {"plaintext": "SID Path", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    let typeStyle = e.type === "KEY" ? {"fontWeight": "bold"} : {"color": "#999"};
                    rows.push({
                        "Type": {"plaintext": e.type, "cellStyle": typeStyle},
                        "GUID / Name": {"plaintext": e.guid, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                        "Details": {"plaintext": e.details},
                        "SID Path": {"plaintext": e.sid, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "DPAPI Master Keys \u2014 " + entries.length + " files"});
            }
        }
        // Parse Chrome/Edge keys
        if(hasChromeKey){
            let entries = [];
            let currentBrowser = "";
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                let browserMatch = trimmed.match(/^\[(\w+)\]\s+Encryption Key:/);
                if(browserMatch){
                    currentBrowser = browserMatch[1];
                    continue;
                }
                let hexMatch = trimmed.match(/^Hex:\s+(.*)/);
                if(hexMatch && currentBrowser){
                    entries.push({browser: currentBrowser, format: "Hex", key: hexMatch[1]});
                }
                let b64Match = trimmed.match(/^B64:\s+(.*)/);
                if(b64Match && currentBrowser){
                    entries.push({browser: currentBrowser, format: "Base64", key: b64Match[1]});
                }
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Browser", "type": "string", "width": 100},
                    {"plaintext": "Format", "type": "string", "width": 80},
                    {"plaintext": "Key", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    rows.push({
                        "Browser": {"plaintext": e.browser, "cellStyle": {"fontWeight": "bold"}},
                        "Format": {"plaintext": e.format},
                        "Key": {"plaintext": e.key, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}},
                        "rowStyle": {"backgroundColor": "rgba(255,165,0,0.08)"}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "Chrome/Edge Encryption Keys"});
            }
        }
        // Parse decryption result
        if(hasDecrypt){
            let entries = [];
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                let kvMatch = trimmed.match(/^(.+?):\s+(.*)/);
                if(kvMatch && !trimmed.startsWith("===")){
                    entries.push({key: kvMatch[1].trim(), value: kvMatch[2].trim()});
                }
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Property", "type": "string", "width": 160},
                    {"plaintext": "Value", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    let isPlaintext = e.key.startsWith("Plaintext");
                    rows.push({
                        "Property": {"plaintext": e.key, "cellStyle": {"fontWeight": "bold"}},
                        "Value": {"plaintext": e.value, "copyIcon": true, "cellStyle": isPlaintext ? {"fontFamily": "monospace", "color": "#4caf50", "fontWeight": "bold"} : {"fontFamily": "monospace"}},
                        "rowStyle": isPlaintext ? {"backgroundColor": "rgba(76,175,80,0.08)"} : {}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "DPAPI Decryption Result"});
            }
        }
        if(tables.length === 0){
            return {"plaintext": combined};
        }
        return {"table": tables};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
