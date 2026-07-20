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
            {"plaintext": "run_as", "type": "string", "width": 140},
            {"plaintext": "task_to_run", "type": "string", "width": 260},
            {"plaintext": "author", "type": "string", "width": 130},
            {"plaintext": "state", "type": "string", "width": 80},
            {"plaintext": "last_result", "type": "string", "width": 80},
            {"plaintext": "last_run", "type": "string", "width": 140},
            {"plaintext": "logon_mode", "type": "string", "width": 130},
            {"plaintext": "enabled", "type": "string", "width": 60},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let rowStyle = {};
            if(stateColors[e.state]){
                rowStyle = {"backgroundColor": stateColors[e.state]};
            }

            // Highlight privileged run-as accounts in red
            let runAs = e.run_as_user || "";
            let runAsStyle = {};
            let runAsLower = runAs.toLowerCase();
            if(runAsLower === "system" || runAsLower.includes("\\system") ||
               runAsLower === "local service" || runAsLower === "network service"){
                runAsStyle = {"fontWeight": "bold", "color": "#f44336"};
            }

            // Highlight user-writable paths in orange (privesc: replace binary)
            let taskToRun = e.task_to_run || "";
            let taskStyle = {};
            let taskLower = taskToRun.toLowerCase();
            if(taskLower.includes("\\users\\") || taskLower.includes("\\programdata\\") ||
               taskLower.includes("\\temp\\") || taskLower.includes("\\tmp\\") ||
               taskLower.includes("\\appdata\\")){
                taskStyle = {"color": "#FF9800", "fontWeight": "bold"};
            }

            // Highlight non-zero last result (broken tasks = potential targets)
            let lastResult = e.last_result || "";
            let resultStyle = {};
            if(lastResult && lastResult !== "0" && lastResult !== "N/A"){
                resultStyle = {"color": "#FF9800"};
            }

            // Build tooltip with extra details (start_in, comment)
            let nameTooltip = e.name;
            if(e.start_in) nameTooltip += "\nStart In: " + e.start_in;
            if(e.comment) nameTooltip += "\nComment: " + e.comment;

            rows.push({
                "actions": {
                    "button": {
                        "name": "Actions",
                        "type": "menu",
                        "startIcon": "settings",
                        "value": [
                            {
                                "name": "Query Details",
                                "type": "task",
                                "ui_feature": "schtask",
                                "startIcon": "search",
                                "parameters": {"action": "query", "name": e.name},
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
                            {
                                "name": "Delete Task",
                                "type": "task",
                                "ui_feature": "schtask",
                                "startIcon": "delete",
                                "getConfirmation": true,
                                "parameters": {"action": "delete", "name": e.name},
                            },
                        ]
                    }
                },
                "name": {"plaintext": e.name, "copyIcon": true},
                "run_as": {"plaintext": runAs, "cellStyle": runAsStyle},
                "task_to_run": {"plaintext": taskToRun, "cellStyle": taskStyle, "copyIcon": true},
                "author": {"plaintext": e.author || ""},
                "state": {"plaintext": e.state},
                "last_result": {"plaintext": lastResult, "cellStyle": resultStyle},
                "last_run": {"plaintext": e.last_run_time || ""},
                "logon_mode": {"plaintext": e.logon_mode || ""},
                "enabled": {"plaintext": e.enabled},
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
