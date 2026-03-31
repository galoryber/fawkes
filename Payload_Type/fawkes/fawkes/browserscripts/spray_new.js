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
        if(data.length === 0){
            return {"plaintext": "No results"};
        }
        // Detect format: sprayResult (username/success/message) vs sprayEnumEntry (username/status/message)
        let isEnum = data[0].hasOwnProperty("status");
        if(isEnum){
            let headers = [
                {"plaintext": "Username", "type": "string", "fillWidth": true},
                {"plaintext": "Status", "type": "string", "width": 130},
                {"plaintext": "Message", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            let existsCount = 0;
            let asrepCount = 0;
            for(let j = 0; j < data.length; j++){
                let entry = data[j];
                let rowStyle = {};
                if(entry.status === "exists"){
                    rowStyle = {"backgroundColor": "rgba(76,175,80,0.1)"};
                    existsCount++;
                } else if(entry.status === "asrep"){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.15)"};
                    asrepCount++;
                } else if(entry.status === "not_found"){
                    rowStyle = {"backgroundColor": "rgba(0,0,0,0.03)"};
                }
                let statusStyle = {};
                if(entry.status === "asrep"){
                    statusStyle = {"fontWeight": "bold", "color": "#ff8c00"};
                }
                rows.push({
                    "Username": {"plaintext": entry.username, "copyIcon": true},
                    "Status": {"plaintext": entry.status, "cellStyle": statusStyle},
                    "Message": {"plaintext": entry.message || ""},
                    "rowStyle": rowStyle,
                });
            }
            let title = "User Enumeration (" + data.length + " users";
            if(existsCount > 0) title += ", " + existsCount + " exist";
            if(asrepCount > 0) title += ", " + asrepCount + " AS-REP";
            title += ")";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        } else {
            let headers = [
                {"plaintext": "Username", "type": "string", "fillWidth": true},
                {"plaintext": "Result", "type": "string", "width": 100},
                {"plaintext": "Message", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            let successCount = 0;
            for(let j = 0; j < data.length; j++){
                let entry = data[j];
                let rowStyle = {};
                let resultText = "FAIL";
                let resultStyle = {};
                if(entry.success){
                    rowStyle = {"backgroundColor": "rgba(76,175,80,0.15)"};
                    resultText = "SUCCESS";
                    resultStyle = {"fontWeight": "bold", "color": "#4caf50"};
                    successCount++;
                }
                rows.push({
                    "Username": {"plaintext": entry.username, "copyIcon": true},
                    "Result": {"plaintext": resultText, "cellStyle": resultStyle},
                    "Message": {"plaintext": entry.message || ""},
                    "rowStyle": rowStyle,
                });
            }
            let title = "Password Spray (" + data.length + " tested, " + successCount + " success)";
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
