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
        // Detect which action produced this output
        // Query action: lines like [N] timestamp | EventID: XXXX | Level | Provider
        let eventMatch = combined.match(/^\[(\d+)\]\s+/m);
        if(eventMatch){
            return renderQueryResults(combined);
        }
        // List action: "Event Log Channels (N" followed by channel names
        if(combined.match(/Event Log Channels/)){
            return renderChannelList(combined);
        }
        // Info action: "Event Log Info:" with Records/File Size/Last Write
        if(combined.match(/Event Log Info:/)){
            return renderLogInfo(combined);
        }
        // Fallback for clear/enable/disable or unrecognized
        return {"plaintext": combined};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
    function renderQueryResults(text){
        let lines = text.split("\n");
        let headers = [
            {"plaintext": "#", "type": "number", "width": 60},
            {"plaintext": "Timestamp", "type": "string", "width": 180},
            {"plaintext": "EventID", "type": "number", "width": 90},
            {"plaintext": "Level", "type": "string", "width": 100},
            {"plaintext": "Provider", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let levelColors = {
            "Critical": "rgba(211,47,47,0.2)",
            "Error": "rgba(244,67,54,0.15)",
            "Warning": "rgba(255,152,0,0.15)",
            "Verbose": "rgba(158,158,158,0.1)",
        };
        let channel = "";
        let channelMatch = text.match(/Events from '([^']+)'/);
        if(channelMatch) channel = channelMatch[1];
        for(let i = 0; i < lines.length; i++){
            // Parse: [N] timestamp | EventID: XXXX | Level | Provider
            let m = lines[i].match(/^\[(\d+)\]\s+(.+?)\s*\|\s*EventID:\s*(\d+)\s*\|\s*(\w+)\s*\|\s*(.+)/);
            if(!m) continue;
            let num = parseInt(m[1]);
            let timestamp = m[2].trim();
            let eventId = parseInt(m[3]);
            let level = m[4].trim();
            let provider = m[5].trim();
            let rowStyle = {};
            if(levelColors[level]){
                rowStyle = {"backgroundColor": levelColors[level]};
            }
            rows.push({
                "#": {"plaintext": String(num)},
                "Timestamp": {"plaintext": timestamp},
                "EventID": {"plaintext": String(eventId), "copyIcon": true},
                "Level": {"plaintext": level},
                "Provider": {"plaintext": provider},
                "rowStyle": rowStyle,
            });
        }
        if(rows.length === 0){
            return {"plaintext": text};
        }
        let title = "Event Log Query";
        if(channel) title += " \u2014 " + channel;
        title += " (" + rows.length + " events)";
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    }
    function renderChannelList(text){
        let lines = text.split("\n");
        let headers = [
            {"plaintext": "#", "type": "number", "width": 60},
            {"plaintext": "Channel", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let idx = 0;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            // Skip header and empty lines
            if(!line || line.startsWith("Event Log") || line.startsWith("No event")) continue;
            idx++;
            rows.push({
                "#": {"plaintext": String(idx)},
                "Channel": {"plaintext": line, "copyIcon": true},
                "rowStyle": {},
            });
        }
        if(rows.length === 0){
            return {"plaintext": text};
        }
        let countMatch = text.match(/Event Log Channels \((\d+)/);
        let title = "Event Log Channels \u2014 " + rows.length;
        if(countMatch) title = "Event Log Channels \u2014 " + countMatch[1];
        let filterMatch = text.match(/filter: '([^']+)'/);
        if(filterMatch) title += " (filter: " + filterMatch[1] + ")";
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    }
    function renderLogInfo(text){
        let lines = text.split("\n");
        let headers = [
            {"plaintext": "Property", "type": "string", "width": 180},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let channelMatch = text.match(/Event Log Info:\s+(.+)/);
        for(let i = 0; i < lines.length; i++){
            let m = lines[i].match(/^\s+(Records|File Size|Last Write):\s+(.+)/);
            if(m){
                rows.push({
                    "Property": {"plaintext": m[1]},
                    "Value": {"plaintext": m[2].trim(), "copyIcon": true},
                    "rowStyle": {},
                });
            }
        }
        if(rows.length === 0){
            return {"plaintext": text};
        }
        let title = "Event Log Info";
        if(channelMatch) title += " \u2014 " + channelMatch[1].trim();
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": title,
            }]
        };
    }
}
