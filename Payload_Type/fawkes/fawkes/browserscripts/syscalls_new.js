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
    let title = "syscalls";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.action) title += " — " + params.action;
        } catch(e){}
    }
    // Extract resolved count
    let m = combined.match(/Resolved:\s*(\d+)/);
    if(m) title += " (" + m[1] + " resolved)";
    return {"plaintext": combined, "title": title};
}
