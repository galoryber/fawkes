function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = responses.reduce((prev, cur) => prev + cur, "");
    let title = "ln";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.source && params.dest) title += " — " + params.source + " → " + params.dest;
        } catch(e){}
    }
    return {"plaintext": combined, "title": title};
}
