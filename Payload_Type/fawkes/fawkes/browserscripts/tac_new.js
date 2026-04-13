function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = responses.reduce((prev, cur) => prev + cur, "");
    let title = "tac";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.path) title += " — " + params.path;
        } catch(e){}
    }
    let lines = combined.split("\n").filter(l => l.length > 0);
    title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
