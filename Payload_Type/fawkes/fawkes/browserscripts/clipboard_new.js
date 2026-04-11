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
        // Parse clipboard monitor/dump captures
        let captures = combined.match(/--- Capture #\d+ \[\d{2}:\d{2}:\d{2}\] ---[\s\S]*?(?=--- Capture #|$)/g);
        if(!captures || captures.length === 0){
            return {"plaintext": combined};
        }
        // Extract status line
        let statusLine = "";
        let lines = combined.split("\n");
        if(lines.length > 0 && (lines[0].includes("monitor") || lines[0].includes("Monitor"))){
            statusLine = lines[0];
            if(lines[1] && lines[1].includes("Duration")){
                statusLine += " | " + lines[1].trim();
            }
        }
        let headers = [
            {"plaintext": "#", "type": "number", "width": 50},
            {"plaintext": "Time", "type": "string", "width": 90},
            {"plaintext": "Tags", "type": "string", "width": 200},
            {"plaintext": "Content", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let c of captures){
            let numMatch = c.match(/Capture #(\d+)/);
            let timeMatch = c.match(/\[(\d{2}:\d{2}:\d{2})\]/);
            let tagsMatch = c.match(/Tags: (.+)/);
            let num = numMatch ? numMatch[1] : "?";
            let time = timeMatch ? timeMatch[1] : "";
            let tags = tagsMatch ? tagsMatch[1] : "";
            // Content is everything after the header line and optional tags line
            let contentLines = c.split("\n");
            let startIdx = 1;
            if(contentLines[1] && contentLines[1].trim().startsWith("Tags:")) startIdx = 2;
            let content = contentLines.slice(startIdx).join("\n").trim();
            if(content.length > 500) content = content.substring(0, 500) + "...";
            let rowStyle = {};
            if(tags.includes("credential") || tags.includes("password") || tags.includes("token")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            }
            rows.push({
                "#": {"plaintext": num},
                "Time": {"plaintext": time},
                "Tags": {"plaintext": tags},
                "Content": {"plaintext": content, "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        let title = "Clipboard Captures (" + rows.length + ")";
        if(statusLine) title = statusLine;
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
