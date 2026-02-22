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
        let data = JSON.parse(combined);
        let headers = [
            {"plaintext": "pid", "type": "number", "width": 90},
            {"plaintext": "ppid", "type": "number", "width": 90},
            {"plaintext": "arch", "type": "string", "width": 80},
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "user", "type": "string", "fillWidth": true},
            {"plaintext": "details", "type": "button", "width": 100, "disableSort": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let proc = data[j];
            let user = proc["user"] || "N/A";
            let rowStyle = {};

            rows.push({
                "pid": {"plaintext": proc["process_id"], "copyIcon": true},
                "ppid": {"plaintext": proc["parent_process_id"]},
                "arch": {"plaintext": proc["architecture"]},
                "name": {"plaintext": proc["name"]},
                "user": {"plaintext": user},
                "rowStyle": rowStyle,
                "details": {
                    "button": {
                        "name": "",
                        "type": "dictionary",
                        "value": {
                            "PID": proc["process_id"],
                            "PPID": proc["parent_process_id"],
                            "Name": proc["name"],
                            "Binary Path": proc["bin_path"] || "N/A",
                            "Command Line": proc["command_line"] || "N/A",
                            "User": user,
                            "Architecture": proc["architecture"],
                        },
                        "hoverText": "View process details",
                        "startIcon": "list",
                    }
                }
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Process Listing (" + data.length + " processes)",
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
