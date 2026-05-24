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
            return {"plaintext": "No services found"};
        }
        let headers = [
            {"plaintext": "actions", "type": "button", "width": 90, "disableSort": true},
            {"plaintext": "name", "type": "string", "width": 300},
            {"plaintext": "state", "type": "string", "width": 100},
            {"plaintext": "display_name", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(e.state === "Running"){
                rowStyle = {"backgroundColor": "rgba(100,149,237,0.15)"};
            } else if(e.state === "Stopped"){
                rowStyle = {};
            }
            let isRunning = e.state === "Running";
            rows.push({
                "actions": {
                    "button": {
                        "name": "Actions",
                        "type": "menu",
                        "startIcon": "settings",
                        "value": [
                            {
                                "name": isRunning ? "Stop Service" : "Start Service",
                                "type": "task",
                                "ui_feature": "service",
                                "startIcon": isRunning ? "stop" : "play",
                                "parameters": {"action": isRunning ? "stop" : "start", "name": e.name},
                            },
                            {
                                "name": "Query Service",
                                "type": "task",
                                "ui_feature": "service",
                                "startIcon": "list",
                                "parameters": {"action": "query", "name": e.name},
                            },
                            {
                                "name": "Delete Service",
                                "type": "task",
                                "ui_feature": "service",
                                "startIcon": "delete",
                                "getConfirmation": true,
                                "parameters": {"action": "delete", "name": e.name},
                            },
                        ]
                    }
                },
                "name": {"plaintext": e.name, "copyIcon": true},
                "state": {"plaintext": e.state},
                "display_name": {"plaintext": e.display_name},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Windows Services (" + data.length + ")",
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
