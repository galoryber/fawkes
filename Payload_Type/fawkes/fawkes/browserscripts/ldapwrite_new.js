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
    let title = "ldap-write";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.action) title += " — " + params.action;
            if(params.target) title += " on " + params.target;
        } catch(e){}
    }
    if(combined.toLowerCase().includes("success")) title += " ✓";
    return {"plaintext": combined, "title": title};
}
