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
        let data;
        try { data = JSON.parse(combined); } catch(e) { return {"plaintext": combined}; }
        if(!Array.isArray(data) || data.length === 0){
            return {"plaintext": "No processes found"};
        }

        // Build a map of pid -> children for tree indentation
        let pidMap = {};
        let childMap = {};
        for(let j = 0; j < data.length; j++){
            pidMap[data[j].pid] = data[j];
            if(!childMap[data[j].ppid]){
                childMap[data[j].ppid] = [];
            }
            childMap[data[j].ppid].push(data[j]);
        }

        // Calculate depth for indentation
        function getDepth(proc, visited){
            if(!visited) visited = {};
            if(visited[proc.pid]) return 0; // prevent cycles
            visited[proc.pid] = true;
            if(!pidMap[proc.ppid] || proc.ppid === proc.pid || proc.ppid === 0){
                return 0;
            }
            return 1 + getDepth(pidMap[proc.ppid], visited);
        }

        // Sort by tree structure: walk the tree from roots
        let ordered = [];
        let seen = {};
        function walkTree(pid, depth){
            if(seen[pid]) return;
            seen[pid] = true;
            if(pidMap[pid]){
                pidMap[pid]._depth = depth;
                ordered.push(pidMap[pid]);
            }
            if(childMap[pid]){
                // Sort children by PID for consistent ordering
                childMap[pid].sort(function(a, b){ return a.pid - b.pid; });
                for(let c = 0; c < childMap[pid].length; c++){
                    walkTree(childMap[pid][c].pid, depth + 1);
                }
            }
        }

        // Find root processes (ppid not in pidMap or ppid === 0)
        let roots = [];
        for(let j = 0; j < data.length; j++){
            if(!pidMap[data[j].ppid] || data[j].ppid === 0 || data[j].ppid === data[j].pid){
                roots.push(data[j].pid);
            }
        }
        roots.sort(function(a, b){ return a - b; });
        for(let r = 0; r < roots.length; r++){
            walkTree(roots[r], 0);
        }
        // Add any orphans not yet walked (cycle protection)
        for(let j = 0; j < data.length; j++){
            if(!seen[data[j].pid]){
                data[j]._depth = 0;
                ordered.push(data[j]);
            }
        }

        let headers = [
            {"plaintext": "PID", "type": "number", "width": 90},
            {"plaintext": "PPID", "type": "number", "width": 90},
            {"plaintext": "Name", "type": "string", "fillWidth": true},
            {"plaintext": "User", "type": "string", "width": 200},
            {"plaintext": "CommandLine", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let j = 0; j < ordered.length; j++){
            let proc = ordered[j];
            let depth = proc._depth || 0;
            let indent = "";
            for(let d = 0; d < depth; d++){
                indent += "\u2502 ";
            }
            if(depth > 0){
                indent = indent.substring(0, indent.length - 2) + "\u251C\u2500";
            }
            let user = proc.user || "N/A";
            let rowStyle = {};
            // Highlight SYSTEM processes
            let lowerUser = user.toLowerCase();
            if(lowerUser === "system" || lowerUser === "nt authority\\system" || lowerUser === "nt authority\\local service" || lowerUser === "nt authority\\network service"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            }

            rows.push({
                "PID": {"plaintext": proc.pid, "copyIcon": true},
                "PPID": {"plaintext": proc.ppid},
                "Name": {"plaintext": indent + (proc.name || "Unknown"), "copyIcon": true},
                "User": {"plaintext": user, "copyIcon": true},
                "CommandLine": {"plaintext": proc.cmdline || "", "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Process Tree (" + data.length + " processes)",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
