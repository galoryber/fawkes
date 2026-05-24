function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    let combined = responses.reduce((prev, cur) => prev + cur, "");
    let title = "audio-capture";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.duration) title += " — " + params.duration + "s";
        } catch(e){}
    }
    if(combined.toLowerCase().includes("success") || combined.toLowerCase().includes("uploaded")) title += " ✓";
    return {"plaintext": combined, "title": title};
}
