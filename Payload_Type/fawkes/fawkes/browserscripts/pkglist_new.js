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
        // Parse package list: "    PackageName                          Version"
        let lines = combined.split("\n");
        let packages = [];
        let headerInfo = "";
        for(let line of lines){
            // Match indented package lines with name and version
            let pkgMatch = line.match(/^\s{4}(\S.+?)\s{2,}(\S+)\s*$/);
            if(pkgMatch){
                packages.push({name: pkgMatch[1].trim(), version: pkgMatch[2].trim()});
            }
            // Capture header/count line
            if(line.includes("Installed") || line.includes("packages")){
                headerInfo = line.trim();
            }
        }
        if(packages.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Package", "type": "string", "fillWidth": true},
            {"plaintext": "Version", "type": "string", "width": 200},
        ];
        let rows = packages.map(function(p){
            return {
                "Package": {"plaintext": p.name, "copyIcon": true},
                "Version": {"plaintext": p.version},
                "rowStyle": {},
            };
        });
        let title = headerInfo || "Installed Packages (" + packages.length + ")";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
