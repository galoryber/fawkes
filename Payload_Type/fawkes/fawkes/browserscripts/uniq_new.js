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
    let title = "uniq";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.path) title += " \u2014 " + params.path;
        } catch(e){}
    }
    title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
