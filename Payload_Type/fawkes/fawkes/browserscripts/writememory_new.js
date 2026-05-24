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
    let title = "writememory";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.pid) title += " — PID " + params.pid;
            if(params.address) title += " @ " + params.address;
        } catch(e){}
    }
    if(combined.toLowerCase().includes("success")) title += " ✓";
    return {"plaintext": combined, "title": title};
}
