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
        let data;
        try { data = JSON.parse(combined); } catch(e) { return {"plaintext": combined}; }
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No IDEs found"};
        }
        let headers = [
            {"plaintext": "IDE", "type": "string", "width": 200},
            {"plaintext": "Version", "type": "string", "width": 120},
            {"plaintext": "Path", "type": "string", "fillWidth": true},
            {"plaintext": "Extensions", "type": "number", "width": 100},
            {"plaintext": "Notable Settings", "type": "string", "fillWidth": true},
            {"plaintext": "details", "type": "button", "width": 100, "disableSort": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let extCount = 0;
            let extList = "";
            if(Array.isArray(e.extensions)){
                extCount = e.extensions.length;
                extList = e.extensions.join(", ");
            }
            let settings = "";
            if(typeof e.settings === "object" && e.settings !== null){
                let keys = Object.keys(e.settings);
                let parts = [];
                for(let k = 0; k < keys.length; k++){
                    parts.push(keys[k] + ": " + e.settings[keys[k]]);
                }
                settings = parts.join("; ");
            } else if(typeof e.settings === "string"){
                settings = e.settings;
            }
            let rowStyle = {};
            // Highlight IDEs with many extensions (potential for credential/secret plugins)
            if(extCount > 20){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
            }
            rows.push({
                "IDE": {"plaintext": e.ide || "Unknown", "copyIcon": true},
                "Version": {"plaintext": e.version || "N/A"},
                "Path": {"plaintext": e.path || "N/A", "copyIcon": true},
                "Extensions": {"plaintext": extCount},
                "Notable Settings": {"plaintext": settings || "N/A"},
                "rowStyle": rowStyle,
                "details": {
                    "button": {
                        "name": "",
                        "type": "dictionary",
                        "value": {
                            "IDE": e.ide || "Unknown",
                            "Version": e.version || "N/A",
                            "Path": e.path || "N/A",
                            "Extension Count": extCount,
                            "Extensions": extList || "None",
                            "Settings": settings || "None",
                        },
                        "hoverText": "View IDE details",
                        "startIcon": "list",
                    }
                }
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "IDE Reconnaissance (" + data.length + " IDEs found)",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
