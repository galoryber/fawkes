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
    let title = "watchdir";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.path) title += " — " + params.path;
            if(params.duration) title += " (" + params.duration + "s)";
        } catch(e){}
    }
    // Extract change count from report
    let m = combined.match(/Changes:\s*(\d+)\s*total/);
    if(m) title += " — " + m[1] + " changes";
    return {"plaintext": combined, "title": title};
}
