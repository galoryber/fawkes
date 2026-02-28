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
            return {"plaintext": "No results"};
        }
        // Detect format: groups (have "comment" field) vs members (have "type" and "group" fields)
        if(data[0].type !== undefined && data[0].group !== undefined){
            // Members view
            let typeColors = {
                "User": "rgba(0,200,0,0.1)",
                "Group": "rgba(100,149,237,0.12)",
                "WellKnownGroup": "rgba(255,165,0,0.12)",
                "Computer": "rgba(200,200,200,0.12)",
            };
            let headers = [
                {"plaintext": "name", "type": "string", "fillWidth": true},
                {"plaintext": "type", "type": "string", "width": 120},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                let rowStyle = {};
                if(typeColors[e.type]){
                    rowStyle = {"backgroundColor": typeColors[e.type]};
                }
                rows.push({
                    "name": {"plaintext": e.name, "copyIcon": true},
                    "type": {"plaintext": e.type},
                    "rowStyle": rowStyle,
                });
            }
            let group = data[0].group || "?";
            let server = data[0].server || "localhost";
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Members of " + server + "\\" + group + " — " + data.length + " member(s)",
                }]
            };
        } else {
            // Groups list view
            let headers = [
                {"plaintext": "name", "type": "string", "fillWidth": true},
                {"plaintext": "comment", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let j = 0; j < data.length; j++){
                let e = data[j];
                rows.push({
                    "name": {"plaintext": e.name, "copyIcon": true},
                    "comment": {"plaintext": e.comment || ""},
                });
            }
            let server = data[0].server || "localhost";
            return {
                "table": [{
                    "headers": headers,
                    "rows": rows,
                    "title": "Local Groups on " + server + " — " + data.length + " group(s)",
                }]
            };
        }
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
