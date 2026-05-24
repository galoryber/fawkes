function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }
    try {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        // Hexdump output is already formatted — show in monospace with line count
        let lines = combined.split("\n").filter(l => l.trim().length > 0);
        let title = "Hexdump";
        if(task.original_params){
            try {
                let params = JSON.parse(task.original_params);
                if(params.path) title += " \u2014 " + params.path;
            } catch(e){}
        }
        title += " (" + lines.length + " lines)";
        return {"plaintext": combined, "title": title};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
