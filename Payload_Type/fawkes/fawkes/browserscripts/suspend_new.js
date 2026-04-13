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
    let title = "suspend";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.action) title += " — " + params.action;
            if(params.pid) title += " PID " + params.pid;
        } catch(e){}
    }
    return {"plaintext": combined, "title": title};
}
