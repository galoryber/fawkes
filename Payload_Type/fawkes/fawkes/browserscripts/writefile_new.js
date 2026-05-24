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
    let title = "writefile";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.path) title += " — " + params.path;
        } catch(e){}
    }
    // Extract byte count
    let m = combined.match(/(\d+)\s*bytes/);
    if(m) title += " (" + m[1] + " bytes)";
    return {"plaintext": combined, "title": title};
}
