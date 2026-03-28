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
        if(!combined.includes("TLS Certificate Check")){
            return {"plaintext": combined};
        }
        let tables = [];
        // Extract connection info
        let tlsVersion = "";
        let cipherSuite = "";
        let certCount = "";
        let tlsMatch = combined.match(/TLS Version:\s+(.+)/);
        if(tlsMatch) tlsVersion = tlsMatch[1].trim();
        let cipherMatch = combined.match(/Cipher Suite:\s+(.+)/);
        if(cipherMatch) cipherSuite = cipherMatch[1].trim();
        let countMatch = combined.match(/Certificates:\s+(\d+)/);
        if(countMatch) certCount = countMatch[1];

        // Connection summary table
        let connHeaders = [
            {"plaintext": "Property", "type": "string", "width": 150},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let connRows = [];
        if(tlsVersion){
            let style = {};
            if(tlsVersion === "TLS 1.0" || tlsVersion === "TLS 1.1"){
                style = {"backgroundColor": "rgba(255,0,0,0.12)"};
            } else if(tlsVersion === "TLS 1.3"){
                style = {"backgroundColor": "rgba(0,200,0,0.08)"};
            }
            connRows.push({"Property": {"plaintext": "TLS Version"}, "Value": {"plaintext": tlsVersion}, "rowStyle": style});
        }
        if(cipherSuite) connRows.push({"Property": {"plaintext": "Cipher Suite"}, "Value": {"plaintext": cipherSuite, "copyIcon": true}});
        if(certCount) connRows.push({"Property": {"plaintext": "Chain Length"}, "Value": {"plaintext": certCount + " certificates"}});

        // Parse individual certificates
        let certSections = combined.split(/---\s*(Leaf Certificate|Certificate #\d+.*?)---/);
        // certSections alternates: [pre-header, header, body, header, body, ...]
        for(let s = 1; s < certSections.length; s += 2){
            let certLabel = certSections[s].trim();
            let certBody = certSections[s + 1] || "";
            let certHeaders = [
                {"plaintext": "Field", "type": "string", "width": 130},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let certRows = [];
            let lines = certBody.split("\n");
            for(let l = 0; l < lines.length; l++){
                let line = lines[l].trim();
                if(!line || line.startsWith("SANs:")) continue;
                // Parse key: value format
                let colonIdx = line.indexOf(":");
                if(colonIdx < 0) continue;
                let key = line.substring(0, colonIdx).trim();
                let val = line.substring(colonIdx + 1).trim();
                if(!key || key === "DNS" || key === "IP"){
                    // SAN entries
                    if(key === "DNS" || key === "IP"){
                        certRows.push({
                            "Field": {"plaintext": "SAN (" + key + ")"},
                            "Value": {"plaintext": val, "copyIcon": true},
                        });
                    }
                    continue;
                }
                let rowStyle = {};
                if(key === "Validity"){
                    if(val.includes("EXPIRED")){
                        rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                    } else if(val.includes("NOT YET VALID")){
                        rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                    } else {
                        rowStyle = {"backgroundColor": "rgba(0,200,0,0.08)"};
                    }
                }
                if(key === "Self-Signed" && val === "YES"){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                }
                if(key === "Host Match"){
                    if(val.includes("MISMATCH")){
                        rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
                    } else {
                        rowStyle = {"backgroundColor": "rgba(0,200,0,0.08)"};
                    }
                }
                let copyIcon = key === "Subject" || key === "SHA256" || key === "Serial";
                certRows.push({
                    "Field": {"plaintext": key},
                    "Value": {"plaintext": val, "copyIcon": copyIcon},
                    "rowStyle": rowStyle,
                });
            }
            if(certRows.length > 0){
                certRows.forEach(r => { if(!r.rowStyle) r.rowStyle = {}; });
                tables.push({
                    "headers": certHeaders,
                    "rows": certRows,
                    "title": certLabel,
                });
            }
        }
        if(connRows.length > 0){
            tables.unshift({"headers": connHeaders, "rows": connRows, "title": "TLS Connection"});
        }
        if(tables.length > 0){
            return {"table": tables};
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
