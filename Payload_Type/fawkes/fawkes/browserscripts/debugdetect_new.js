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
        let entries = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            // Parse: "  !! Name                              Status     Details"
            // or:    "     Name                              Status     Details"
            let match = line.match(/^\s{2}(!!|\?\?|xx|\s{2})\s+(.+?)\s{2,}(DETECTED|WARNING|CLEAN|ERROR)\s*(.*)/);
            if(match){
                entries.push({
                    indicator: match[1].trim(),
                    name: match[2].trim(),
                    status: match[3],
                    details: match[4].trim()
                });
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Status", "type": "string", "width": 110},
            {"plaintext": "Check", "type": "string", "fillWidth": true},
            {"plaintext": "Details", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        let detections = 0;
        let warnings = 0;
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let rowStyle = {};
            let statusStyle = {};
            if(e.status === "DETECTED"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
                statusStyle = {"color": "#ff4444", "fontWeight": "bold"};
                detections++;
            } else if(e.status === "WARNING"){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.08)"};
                statusStyle = {"color": "#ff8c00", "fontWeight": "bold"};
                warnings++;
            } else if(e.status === "ERROR"){
                statusStyle = {"color": "#999"};
            }
            rows.push({
                "Status": {"plaintext": e.status, "cellStyle": statusStyle},
                "Check": {"plaintext": e.name},
                "Details": {"plaintext": e.details, "copyIcon": true},
                "rowStyle": rowStyle
            });
        }
        let title = "Debug Detection (" + entries.length + " checks";
        if(detections > 0) title += ", " + detections + " detected";
        if(warnings > 0) title += ", " + warnings + " warnings";
        title += ")";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
