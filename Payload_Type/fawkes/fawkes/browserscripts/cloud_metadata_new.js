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
        // Parse into sections by provider/category
        let sections = [];
        let currentSection = null;
        let kvEntries = []; // flat list for table
        let providerColors = {
            "AWS": "rgba(255,153,0,0.12)",
            "Azure": "rgba(0,120,212,0.1)",
            "GCP": "rgba(66,133,244,0.1)",
            "DigitalOcean": "rgba(0,105,225,0.1)",
        };
        let sensitiveKeys = new Set(["AccessKeyId", "SecretAccessKey", "Token", "Access Token", "Session Token"]);
        let currentProvider = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            // Section headers: === Title ===
            let sectionMatch = line.match(/^===\s+(.+?)\s+===$/);
            if(sectionMatch){
                currentSection = sectionMatch[1];
                continue;
            }
            // Provider detection: [+] AWS/Azure/GCP/DigitalOcean
            let providerMatch = line.match(/^\[([+*\-])\]\s+(AWS|Azure|GCP|DigitalOcean)\b/i);
            if(providerMatch){
                currentProvider = providerMatch[2];
                if(currentProvider === "DigitalOcean") currentProvider = "DigitalOcean";
                // The rest of the line after provider is a description
                let desc = line.replace(/^\[[+*\-]\]\s+/, "").trim();
                kvEntries.push({
                    provider: currentProvider,
                    key: "Status",
                    value: desc,
                    section: currentSection || "",
                    isSensitive: false,
                    isHeader: true,
                });
                continue;
            }
            // Key-value lines: "    Key:  Value" or "  Key:  Value"
            let kvMatch = line.match(/^\s{2,}(\S[^:]*?):\s+(.+)/);
            if(kvMatch){
                let key = kvMatch[1].trim();
                let value = kvMatch[2].trim();
                let isSensitive = sensitiveKeys.has(key);
                kvEntries.push({
                    provider: currentProvider || "Unknown",
                    key: key,
                    value: value,
                    section: currentSection || "",
                    isSensitive: isSensitive,
                    isHeader: false,
                });
                continue;
            }
            // Negative results: [-] or [*] with no provider
            let statusMatch = line.match(/^\[([+*\-])\]\s+(.+)/);
            if(statusMatch){
                kvEntries.push({
                    provider: currentProvider || "General",
                    key: "Info",
                    value: statusMatch[2].trim(),
                    section: currentSection || "",
                    isSensitive: false,
                    isHeader: true,
                });
            }
        }
        if(kvEntries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Provider", "type": "string", "width": 120},
            {"plaintext": "Key", "type": "string", "width": 180},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
            {"plaintext": "Section", "type": "string", "width": 180},
        ];
        let rows = [];
        // Detect unique providers found
        let providersFound = new Set();
        for(let j = 0; j < kvEntries.length; j++){
            let entry = kvEntries[j];
            if(!entry.isHeader){
                providersFound.add(entry.provider);
            }
            let rowStyle = {};
            let bgColor = providerColors[entry.provider];
            if(entry.isSensitive){
                rowStyle = {"backgroundColor": "rgba(255,87,34,0.15)"};
            } else if(entry.isHeader){
                rowStyle = {"backgroundColor": "rgba(128,128,128,0.08)"};
            } else if(bgColor){
                rowStyle = {"backgroundColor": bgColor};
            }
            rows.push({
                "Provider": {"plaintext": entry.provider},
                "Key": {"plaintext": entry.key, "cellStyle": entry.isSensitive ? {"fontWeight": "bold"} : {}},
                "Value": {"plaintext": entry.value, "copyIcon": entry.isSensitive || !entry.isHeader},
                "Section": {"plaintext": entry.section},
                "rowStyle": rowStyle,
            });
        }
        let providerList = Array.from(providersFound);
        let title = "Cloud Metadata";
        if(providerList.length > 0){
            title += " \u2014 " + providerList.join(", ");
        }
        title += " (" + kvEntries.length + " entries)";
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
