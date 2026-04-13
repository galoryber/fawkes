function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = responses.reduce((prev, cur) => prev + cur, "");
    let title = "sleep";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.interval !== undefined) title += " — " + params.interval + "s";
            if(params.jitter !== undefined) title += " (jitter " + params.jitter + "%)";
        } catch(e){}
    }
    return {"plaintext": combined, "title": title};
}
