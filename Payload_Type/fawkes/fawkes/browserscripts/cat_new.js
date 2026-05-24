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
        // Cat output is typically raw text — wrap in monospace with line numbers
        let lines = combined.split("\n");
        let lineCount = lines.length;
        // For large files, show line count in title
        let title = "File Contents";
        if(task.original_params){
            try {
                let params = JSON.parse(task.original_params);
                if(params.path) title += " \u2014 " + params.path;
            } catch(e){}
        }
        title += " (" + lineCount + " lines)";
        return {
            "plaintext": combined,
            "title": title,
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
