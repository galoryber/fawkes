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
        let lines = combined.split("\n").filter(l => l.trim());
        let rows = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            let rowStyle = {};
            if(line.includes("[+]") || line.includes("SUCCESS") || line.includes("listening")){
                rowStyle = {"backgroundColor": "rgba(0,255,0,0.05)"};
            } else if(line.includes("[!]") || line.includes("ERROR") || line.includes("denied")){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
            } else if(line.includes("[*]")){
                rowStyle = {"backgroundColor": "rgba(0,120,255,0.05)"};
            }
            rows.push({
                "Output": {"plaintext": line},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{
            "headers": [{"plaintext": "Output", "type": "string", "fillWidth": true}],
            "rows": rows,
            "title": "Pipe Server"
        }]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
