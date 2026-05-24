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
    let title = "printspoofer";
    if(combined.includes("SYSTEM") || combined.toLowerCase().includes("success")){
        title += " — SYSTEM ✓";
    } else if(combined.toLowerCase().includes("fail") || combined.toLowerCase().includes("timeout")){
        title += " — Failed";
    }
    return {"plaintext": combined, "title": title};
}
