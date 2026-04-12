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
    let mountCount = 0;
    for(let i = 0; i < lines.length; i++){
        if(lines[i].match(/^\//) || lines[i].match(/^[A-Za-z]:\\/)){
            mountCount++;
        }
    }
    let title = "mount (" + mountCount + " mounts)";
    return {"plaintext": combined, "title": title};
}
