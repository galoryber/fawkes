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
        // LOLBin output: extract interpreter info and execution output
        let interpreterMatch = combined.match(/^\[.\] (?:Using|Executing|Running) (.+)/m);
        let exitMatch = combined.match(/Exit code: (\d+)/);
        let stderrMatch = combined.match(/--- stderr ---\n([\s\S]*?)(?=---|$)/);
        // If structured with sections, parse them
        if(interpreterMatch || exitMatch){
            let fields = [];
            if(interpreterMatch) fields.push(["Interpreter", interpreterMatch[1]]);
            if(exitMatch){
                fields.push(["Exit Code", exitMatch[1]]);
            }
            if(fields.length > 0){
                let headers = [
                    {"plaintext": "Field", "type": "string", "width": 120},
                    {"plaintext": "Value", "type": "string", "fillWidth": true},
                ];
                let rows = fields.map(function(f){
                    let rowStyle = {};
                    if(f[0] === "Exit Code" && f[1] !== "0"){
                        rowStyle = {"backgroundColor": "rgba(255,0,0,0.1)"};
                    }
                    return {
                        "Field": {"plaintext": f[0]},
                        "Value": {"plaintext": f[1], "copyIcon": true},
                        "rowStyle": rowStyle,
                    };
                });
                return {"table": [{"headers": headers, "rows": rows, "title": "LOLBin Execution"}]};
            }
        }
        return {"plaintext": combined};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
