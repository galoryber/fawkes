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
        // Parse search results: [N] timestamp | sender | subject
        let searchResults = combined.match(/\[\d+\] .+/g);
        if(searchResults && searchResults.length > 0 && combined.includes("Search '")){
            let headers = [
                {"plaintext": "#", "type": "number", "width": 50},
                {"plaintext": "Received", "type": "string", "width": 180},
                {"plaintext": "From", "type": "string", "width": 200},
                {"plaintext": "Subject", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let line of searchResults){
                let match = line.match(/\[(\d+)\] (.+?) \| (.+?) \| (.+)/);
                if(match){
                    rows.push({
                        "#": {"plaintext": match[1]},
                        "Received": {"plaintext": match[2]},
                        "From": {"plaintext": match[3], "copyIcon": true},
                        "Subject": {"plaintext": match[4]},
                        "rowStyle": {},
                    });
                }
            }
            let queryMatch = combined.match(/Search '(.+?)': (\d+) matches/);
            let title = "Email Search Results (" + rows.length + ")";
            if(queryMatch) title = "Search '" + queryMatch[1] + "' — " + queryMatch[2] + " matches";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        // Parse email read: Subject/From/To/Received fields
        if(combined.includes("Subject:") && combined.includes("From:") && combined.includes("--- Body ---")){
            let fields = [];
            let fieldPatterns = [
                ["Subject", /^Subject: (.+)/m],
                ["From", /^From: (.+)/m],
                ["To", /^To: (.+)/m],
                ["CC", /^CC: (.+)/m],
                ["Received", /^Received: (.+)/m],
                ["Attachments", /^Attachments: (.+)/m],
            ];
            for(let fp of fieldPatterns){
                let m = combined.match(fp[1]);
                if(m) fields.push([fp[0], m[1]]);
            }
            // Extract attachment lines
            let attachLines = combined.match(/^\s+\[\d+\] .+/gm);
            if(attachLines){
                for(let a of attachLines){
                    fields.push(["  Attachment", a.trim()]);
                }
            }
            let headers = [
                {"plaintext": "Field", "type": "string", "width": 120},
                {"plaintext": "Value", "type": "string", "fillWidth": true},
            ];
            let rows = fields.map(function(f){
                return {
                    "Field": {"plaintext": f[0]},
                    "Value": {"plaintext": f[1], "copyIcon": true},
                    "rowStyle": {},
                };
            });
            let subjectMatch = combined.match(/^Subject: (.+)/m);
            let title = "Email" + (subjectMatch ? ": " + subjectMatch[1] : "");
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        // Folders list or count: return plaintext
        return {"plaintext": combined};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
