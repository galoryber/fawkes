function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = responses.reduce((prev, cur) => prev + cur, "");
    let title = "socks";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.action) title += " — " + params.action;
            if(params.port) title += " :" + params.port;
        } catch(e){}
    }
    return {"plaintext": combined, "title": title};
}
