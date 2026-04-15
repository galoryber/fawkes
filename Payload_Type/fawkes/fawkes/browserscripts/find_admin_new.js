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
            return {"plaintext": "No results — no hosts responded"};
        }
        let headers = [
            {"plaintext": "Host", "type": "string", "fillWidth": true},
            {"plaintext": "Method", "type": "string", "width": 100},
            {"plaintext": "Admin", "type": "string", "width": 100},
            {"plaintext": "Message", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let adminCount = 0;
        for(let j = 0; j < data.length; j++){
            let entry = data[j];
            let rowStyle = {};
            let adminText = "No";
            let adminStyle = {};
            if(entry.admin){
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.15)"};
                adminText = "YES";
                adminStyle = {"fontWeight": "bold", "color": "#4caf50"};
                adminCount++;
            }
            if(entry.message && entry.message.toLowerCase().includes("error")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.06)"};
            }
            rows.push({
                "Host": {"plaintext": entry.host, "copyIcon": true},
                "Method": {"plaintext": entry.method || ""},
                "Admin": {"plaintext": adminText, "cellStyle": adminStyle},
                "Message": {"plaintext": entry.message || ""},
                "rowStyle": rowStyle,
            });
        }
        let title = "Admin Check (" + data.length + " hosts, " + adminCount + " admin)";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}
