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
    let title = "file-type";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.path) title += " — " + params.path;
        } catch(e){}
    }
    let lines = combined.split("\n").filter(l => l.trim().length > 0);
    if(lines.length > 1) title += " (" + lines.length + " files)";
    return {"plaintext": combined, "title": title};
}
