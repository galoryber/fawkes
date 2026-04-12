function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = "";
    for(let i = 0; i < responses.length; i++){
        combined += responses[i];
    }
    let lines = combined.split("\n").filter(l => l.length > 0);
    let title = "cp";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            let parts = [];
            if(params.source) parts.push(params.source);
            if(params.destination) parts.push(params.destination);
            if(parts.length === 2) title += " \u2014 " + parts[0] + " \u2192 " + parts[1];
        } catch(e){}
    }
    title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
