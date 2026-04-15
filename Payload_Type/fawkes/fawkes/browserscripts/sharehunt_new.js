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
        let lines = combined.split("\n");
        let results = [];
        let currentHost = "";
        let totalFiles = 0;
        let totalHosts = 0;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            // Host header: "--- hostname ---"
            let hostMatch = line.match(/^---\s+(\S+)\s+---$/);
            if(hostMatch){
                currentHost = hostMatch[1];
                totalHosts++;
                continue;
            }
            // File result: "  [+] [category] \\host\share\path (size, date)"
            let fileMatch = line.match(/^\[\+\]\s+\[(\w+)\]\s+(.+?)\s+\(([^,]+),\s*(.+?)\)$/);
            if(fileMatch){
                results.push({
                    host: currentHost,
                    category: fileMatch[1],
                    path: fileMatch[2],
                    size: fileMatch[3].trim(),
                    date: fileMatch[4].trim(),
                });
                totalFiles++;
                continue;
            }
            // Error line: "  [!] Error: ..."
            let errMatch = line.match(/^\[!\]\s+Error:\s+(.*)/);
            if(errMatch){
                results.push({
                    host: currentHost,
                    category: "error",
                    path: errMatch[1],
                    size: "",
                    date: "",
                });
            }
        }
        if(results.length === 0){
            return {"plaintext": combined};
        }
        let catColors = {
            "cred": "rgba(255,0,0,0.12)",
            "config": "rgba(255,165,0,0.10)",
            "doc": "rgba(100,149,237,0.08)",
            "error": "rgba(128,128,128,0.10)",
        };
        let headers = [
            {"plaintext": "Host", "type": "string", "width": 140},
            {"plaintext": "Category", "type": "string", "width": 80},
            {"plaintext": "Path", "type": "string", "fillWidth": true},
            {"plaintext": "Size", "type": "string", "width": 80},
            {"plaintext": "Modified", "type": "string", "width": 130},
        ];
        let rows = [];
        for(let j = 0; j < results.length; j++){
            let r = results[j];
            let bg = catColors[r.category] || "";
            let catStyle = {};
            if(r.category === "cred") catStyle = {"color": "#d32f2f", "fontWeight": "bold"};
            else if(r.category === "config") catStyle = {"color": "#ff8c00", "fontWeight": "bold"};
            else if(r.category === "error") catStyle = {"color": "#888", "fontStyle": "italic"};
            rows.push({
                "Host": {"plaintext": r.host},
                "Category": {"plaintext": r.category, "cellStyle": catStyle},
                "Path": {"plaintext": r.path, "copyIcon": true, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                "Size": {"plaintext": r.size},
                "Modified": {"plaintext": r.date},
                "rowStyle": bg ? {"backgroundColor": bg} : {},
            });
        }
        // Category summary
        let cats = {};
        for(let r of results){ if(r.category !== "error") cats[r.category] = (cats[r.category]||0) + 1; }
        let catSummary = Object.entries(cats).map(function(e){ return e[1] + " " + e[0]; }).join(", ");
        let title = "Share Hunt — " + totalFiles + " files across " + totalHosts + " hosts";
        if(catSummary) title += " (" + catSummary + ")";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
