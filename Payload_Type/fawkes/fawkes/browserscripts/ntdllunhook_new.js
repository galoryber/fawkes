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

    let action = "unhook";
    let dll = "";
    if(task.original_params){
        try {
            let params = JSON.parse(task.original_params);
            if(params.action) action = params.action.toLowerCase();
            if(params.dll) dll = params.dll;
        } catch(e){}
    }

    let lines = combined.split("\n").filter(l => l.trim().length > 0);

    if(action === "check"){
        let hookMatches = combined.match(/Found (\d+) hooked regions?/);
        let noHookMatches = combined.match(/No hooks detected/g);
        let hookEntries = [];
        for(let i = 0; i < lines.length; i++){
            let m = lines[i].match(/^\s*(0x[0-9A-Fa-f]+)\s+\((\d+)\s+bytes?\):\s+([0-9A-Fa-f]+)\s+.?\s+([0-9A-Fa-f]+)/);
            if(m){
                hookEntries.push({addr: m[1], size: m[2], original: m[3], hooked: m[4]});
            }
        }
        if(hookEntries.length > 0){
            let headers = [
                {"plaintext": "Address", "type": "string", "width": 160},
                {"plaintext": "Size", "type": "number", "width": 80},
                {"plaintext": "Original", "type": "string", "width": 180},
                {"plaintext": "Hooked", "type": "string", "fillWidth": true},
            ];
            let rows = [];
            for(let i = 0; i < hookEntries.length; i++){
                let h = hookEntries[i];
                rows.push({
                    "Address": {"plaintext": h.addr, "cellStyle": {"fontFamily": "monospace"}},
                    "Size": {"plaintext": h.size + " bytes"},
                    "Original": {"plaintext": h.original, "cellStyle": {"fontFamily": "monospace", "color": "#2ecc71"}},
                    "Hooked": {"plaintext": h.hooked, "cellStyle": {"fontFamily": "monospace", "color": "#e74c3c"}},
                });
            }
            let totalHooks = hookMatches ? hookMatches[1] : hookEntries.length;
            let title = "⚠️ Hooks Detected — " + totalHooks + " hooked regions";
            if(dll) title += " in " + dll;
            return {"table": [{"headers": headers, "rows": rows, "title": title}]};
        }
        if(noHookMatches){
            let title = "✅ Clean — no hooks detected";
            if(dll) title += " in " + dll;
            return {"plaintext": combined, "title": title};
        }
    }

    if(action === "unhook"){
        let restored = combined.match(/Restored (\d+) bytes/);
        let success = combined.includes("successfully unhooked");
        let title = "ntdll-unhook";
        if(dll) title += " — " + dll;
        if(success && restored){
            title += " — ✅ " + restored[1] + " bytes restored";
        }
        return {"plaintext": combined, "title": title};
    }

    let title = "ntdll-unhook";
    if(action !== "unhook") title += " — " + action;
    title += " (" + lines.length + " lines)";
    return {"plaintext": combined, "title": title};
}
