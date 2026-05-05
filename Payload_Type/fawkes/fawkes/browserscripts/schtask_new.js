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
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No scheduled tasks found"};
        }
        let stateColors = {
            "Running": "rgba(0,200,0,0.15)",
            "Disabled": "rgba(255,0,0,0.1)",
            "Queued": "rgba(255,165,0,0.12)",
        };
        let headers = [
            {"plaintext": "actions", "type": "button", "width": 90, "disableSort": true},
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "state", "type": "string", "width": 90},
            {"plaintext": "enabled", "type": "string", "width": 70},
            {"plaintext": "next_run_time", "type": "string", "width": 180},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(stateColors[e.state]){
                rowStyle = {"backgroundColor": stateColors[e.state]};
            }
            rows.push({
                "actions": {
                    "button": {
                        "name": "Actions",
                        "type": "menu",
                        "startIcon": "settings",
                        "value": [
                            {
                                "name": "Delete Task",
                                "type": "task",
                                "ui_feature": "schtask",
                                "startIcon": "delete",
                                "getConfirmation": true,
                                "parameters": {"action": "delete", "name": e.name},
                            },
                            {
                                "name": "Run Now",
                                "type": "task",
                                "ui_feature": "schtask",
                                "startIcon": "play",
                                "parameters": {"action": "run", "name": e.name},
                            },
                            {
                                "name": e.enabled === "true" ? "Disable" : "Enable",
                                "type": "task",
                                "ui_feature": "schtask",
                                "startIcon": e.enabled === "true" ? "stop" : "play",
                                "parameters": {"action": e.enabled === "true" ? "disable" : "enable", "name": e.name},
                            },
                        ]
                    }
                },
                "name": {"plaintext": e.name, "copyIcon": true},
                "state": {"plaintext": e.state},
                "enabled": {"plaintext": e.enabled},
                "next_run_time": {"plaintext": e.next_run_time || ""},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Scheduled Tasks — " + data.length + " task(s)",
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
