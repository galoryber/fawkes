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
        // "check" action: text header + JSON object at the end
        let jsonStart = combined.lastIndexOf("{");
        if(jsonStart >= 0){
            let jsonStr = combined.substring(jsonStart);
            let info;
            try { info = JSON.parse(jsonStr); } catch(e) { info = null; }
            if(info && typeof info.installed !== "undefined"){
                let headers = [
                    {"plaintext": "Property", "type": "string", "width": 200},
                    {"plaintext": "Value", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                function addRow(key, val, style){
                    rows.push({
                        "Property": {"plaintext": key, "cellStyle": {"fontWeight": "bold"}},
                        "Value": {"plaintext": String(val), "cellStyle": style || {}, "copyIcon": true},
                        "rowStyle": {},
                    });
                }
                let installed = info.installed;
                addRow("Installed", installed ? "YES" : "NO", installed ? {"color": "#d32f2f", "fontWeight": "bold"} : {"color": "#4caf50", "fontWeight": "bold"});
                if(installed){
                    addRow("Service Name", info.service_name || "");
                    addRow("Driver Name", info.driver_name || "");
                    let driverLoaded = info.driver_loaded;
                    addRow("Driver Loaded", driverLoaded ? "YES" : "NO", driverLoaded ? {"color": "#d32f2f", "fontWeight": "bold"} : {});
                    addRow("Image Path", info.image_path || "", {"fontFamily": "monospace", "fontSize": "0.9em"});
                    addRow("Version", info.version || "");
                    addRow("Hash Algorithm", info.hash_algorithm || "");
                    addRow("Options", "0x" + (info.options || 0).toString(16).toUpperCase(), {"fontFamily": "monospace"});
                    addRow("Rule Bytes", String(info.rule_bytes || 0));
                }
                let tables = [{"headers": headers, "rows": rows, "title": installed ? "Sysmon Configuration — DETECTED" : "Sysmon — Not Detected"}];
                // Event config table
                if(info.events && Object.keys(info.events).length > 0){
                    let evtHeaders = [
                        {"plaintext": "Event Channel", "type": "string", "fillWidth": true},
                        {"plaintext": "Status", "type": "string", "width": 100},
                    ];
                    let evtRows = [];
                    let evtEntries = Object.entries(info.events);
                    for(let k = 0; k < evtEntries.length; k++){
                        let name = evtEntries[k][0];
                        let status = evtEntries[k][1];
                        let isEnabled = status === "Enabled";
                        evtRows.push({
                            "Event Channel": {"plaintext": name},
                            "Status": {"plaintext": status, "cellStyle": isEnabled ? {"color": "#d32f2f", "fontWeight": "bold"} : {"color": "#888"}},
                            "rowStyle": isEnabled ? {"backgroundColor": "rgba(255,0,0,0.06)"} : {},
                        });
                    }
                    tables.push({"headers": evtHeaders, "rows": evtRows, "title": "Sysmon Event Configuration"});
                }
                return {"table": tables};
            }
        }
        // "events" action: parse event table
        if(combined.includes("=== Sysmon Event Types ===")){
            let lines = combined.split("\n");
            let headers = [
                {"plaintext": "Event ID", "type": "number", "width": 80},
                {"plaintext": "Event Name", "type": "string", "fillWidth": true},
                {"plaintext": "Status", "type": "string", "width": 100},
            ];
            let rows = [];
            for(let i = 0; i < lines.length; i++){
                let m = lines[i].match(/Event\s+(\d+):\s+(.+?)\s+\[(\w+)\]/);
                if(m){
                    let id = m[1];
                    let name = m[2].trim();
                    let status = m[3];
                    let isEnabled = status === "Enabled";
                    rows.push({
                        "Event ID": {"plaintext": id},
                        "Event Name": {"plaintext": name},
                        "Status": {"plaintext": status, "cellStyle": isEnabled ? {"color": "#d32f2f", "fontWeight": "bold"} : {"color": "#888"}},
                        "rowStyle": isEnabled ? {"backgroundColor": "rgba(255,0,0,0.06)"} : {},
                    });
                }
            }
            if(rows.length > 0){
                return {"table": [{"headers": headers, "rows": rows, "title": "Sysmon Event Types"}]};
            }
        }
        return {"plaintext": combined};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
