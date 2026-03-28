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
        // Simple action results (add, remove) — show as plaintext
        if(combined.startsWith("Added cron") || combined.startsWith("Removed ")){
            return {"plaintext": combined};
        }
        if(combined.includes("(empty crontab)")){
            return {"plaintext": combined};
        }
        let lines = combined.split("\n");
        let entries = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("Current crontab")) continue;
            // Parse special shortcuts: @reboot, @daily, @hourly, etc.
            let specialMatch = trimmed.match(/^(@\w+)\s+(.*)/);
            if(specialMatch){
                entries.push({schedule: specialMatch[1], command: specialMatch[2], isSpecial: true});
                continue;
            }
            // Parse standard cron: min hour dom month dow command
            let cronMatch = trimmed.match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/);
            if(cronMatch){
                let sched = cronMatch[1] + " " + cronMatch[2] + " " + cronMatch[3] + " " + cronMatch[4] + " " + cronMatch[5];
                entries.push({schedule: sched, command: cronMatch[6], isSpecial: false});
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Schedule", "type": "string", "width": 180},
            {"plaintext": "Command", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let schedStyle = {"fontFamily": "monospace"};
            let rowStyle = {};
            // Highlight @reboot entries (potential persistence)
            if(e.schedule === "@reboot"){
                schedStyle = {"fontFamily": "monospace", "color": "#d94f00", "fontWeight": "bold"};
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
            }
            rows.push({
                "Schedule": {"plaintext": e.schedule, "cellStyle": schedStyle},
                "Command": {"plaintext": e.command, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Crontab \u2014 " + entries.length + " entries"}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
