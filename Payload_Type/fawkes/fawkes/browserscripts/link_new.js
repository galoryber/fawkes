function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = responses.reduce((prev, cur) => prev + cur, "");
    let title = "link";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.connection_info && params.connection_info.host) title += " — " + params.connection_info.host;
        } catch(e){}
    }
    if(combined.toLowerCase().includes("success") || combined.toLowerCase().includes("linked")) title += " ✓";
    return {"plaintext": combined, "title": title};
}
