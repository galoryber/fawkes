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
        // Parse credential blocks: --- <target> --- followed by key: value lines
        let blocks = combined.split(/^---\s+/m);
        if(blocks.length < 2){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Target", "type": "string", "fillWidth": true},
            {"plaintext": "Type", "type": "string", "width": 140},
            {"plaintext": "Username", "type": "string", "width": 200},
            {"plaintext": "Credential", "type": "string", "width": 200},
            {"plaintext": "Persist", "type": "string", "width": 120},
            {"plaintext": "Details", "type": "button", "width": 100, "disableSort": true},
        ];
        let rows = [];
        let domainCreds = new Set(["Domain Password", "Domain Certificate", "Domain Visible Password"]);
        for(let b = 1; b < blocks.length; b++){
            let block = blocks[b];
            // Target is before the closing ---
            let targetMatch = block.match(/^(.+?)\s*---/);
            if(!targetMatch) continue;
            let target = targetMatch[1].trim();
            // Parse key-value pairs
            let fields = {};
            let fieldLines = block.split("\n");
            for(let fl = 0; fl < fieldLines.length; fl++){
                let m = fieldLines[fl].match(/^\s+(Type|Username|Password|Blob|Comment|Persist):\s+(.+)/);
                if(m){
                    fields[m[1]] = m[2].trim();
                }
            }
            let credValue = fields["Password"] || fields["Blob"] || "\u2014";
            let rowStyle = {};
            // Highlight domain credentials in blue, entries with passwords in green
            if(domainCreds.has(fields["Type"])){
                rowStyle = {"backgroundColor": "rgba(33,150,243,0.1)"};
            }
            if(fields["Password"]){
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.15)"};
            }
            let detailsDict = {"Target": target};
            if(fields["Type"]) detailsDict["Type"] = fields["Type"];
            if(fields["Username"]) detailsDict["Username"] = fields["Username"];
            if(fields["Password"]) detailsDict["Password"] = fields["Password"];
            if(fields["Blob"]) detailsDict["Blob"] = fields["Blob"];
            if(fields["Comment"]) detailsDict["Comment"] = fields["Comment"];
            if(fields["Persist"]) detailsDict["Persist"] = fields["Persist"];
            rows.push({
                "Target": {"plaintext": target, "copyIcon": true},
                "Type": {"plaintext": fields["Type"] || "\u2014"},
                "Username": {"plaintext": fields["Username"] || "\u2014", "copyIcon": true},
                "Credential": {"plaintext": credValue, "copyIcon": fields["Password"] ? true : false},
                "Persist": {"plaintext": fields["Persist"] || "\u2014"},
                "rowStyle": rowStyle,
                "Details": {
                    "button": {
                        "name": "",
                        "type": "dictionary",
                        "value": detailsDict,
                        "hoverText": "View credential details",
                        "startIcon": "list",
                    }
                }
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        // Extract summary line
        let summaryMatch = combined.match(/Summary:\s+(.+)/);
        let title = "Credential Manager \u2014 " + rows.length + " entries";
        if(summaryMatch){
            title += " (" + summaryMatch[1] + ")";
        }
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
