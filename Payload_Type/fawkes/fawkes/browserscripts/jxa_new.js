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
    let lines = combined.split("\n").filter(l => l.length > 0);
    let title = "jxa";
    if(lines.length > 0) title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
