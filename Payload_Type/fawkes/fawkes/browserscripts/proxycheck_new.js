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
        let entries = [];
        let currentSection = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^={10,}/)) continue;
            // Section headers: "[*] Section Name:" or "[-] No proxy..."
            let secMatch = trimmed.match(/^\[\*\]\s+(.*?)(?::?\s*)$/);
            if(secMatch){
                currentSection = secMatch[1].replace(/:$/, "").trim();
                continue;
            }
            // No proxy message
            let noProxy = trimmed.match(/^\[-\]\s+(.*)/);
            if(noProxy){
                entries.push({section: "Summary", setting: noProxy[1], value: "", status: "none"});
                continue;
            }
            // Key-value inside section: "    KEY = VALUE" or "    KEY: VALUE"
            let kvMatch = trimmed.match(/^(\S[\w\s_]*?)\s*[=:]\s+(.*)/);
            if(kvMatch && currentSection){
                entries.push({section: currentSection, setting: kvMatch[1].trim(), value: kvMatch[2].trim(), status: "configured"});
                continue;
            }
            // Status messages: "OK: ..." or "FAILED: ..."
            let okMatch = trimmed.match(/^OK:\s+(.*)/);
            if(okMatch){
                entries.push({section: currentSection, setting: "Result", value: okMatch[1], status: "ok"});
                continue;
            }
            let failMatch = trimmed.match(/^FAILED:\s+(.*)/);
            if(failMatch){
                entries.push({section: currentSection, setting: "Result", value: failMatch[1], status: "fail"});
                continue;
            }
            // Arrow format: "    url → proxy"
            let arrowMatch = trimmed.match(/^(.+?)\s+\u2192\s+(.*)/);
            if(arrowMatch){
                entries.push({section: currentSection, setting: arrowMatch[1], value: arrowMatch[2], status: arrowMatch[2] === "direct" ? "direct" : "configured"});
                continue;
            }
            // Catch-all for "(none set)" etc.
            if(trimmed === "(none set)"){
                entries.push({section: currentSection, setting: "(none set)", value: "", status: "none"});
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Category", "type": "string", "width": 220},
            {"plaintext": "Setting", "type": "string", "width": 200},
            {"plaintext": "Value", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let valStyle = {};
            let rowStyle = {};
            if(e.status === "configured"){
                valStyle = {"fontWeight": "bold", "color": "#4caf50"};
            } else if(e.status === "ok"){
                valStyle = {"color": "#4caf50", "fontWeight": "bold"};
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.08)"};
            } else if(e.status === "fail"){
                valStyle = {"color": "#d94f00", "fontWeight": "bold"};
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
            } else if(e.status === "none"){
                valStyle = {"color": "#999"};
            } else if(e.status === "direct"){
                valStyle = {"color": "#999"};
            }
            rows.push({
                "Category": {"plaintext": e.section, "cellStyle": {"fontWeight": "bold"}},
                "Setting": {"plaintext": e.setting},
                "Value": {"plaintext": e.value, "cellStyle": valStyle, "copyIcon": e.value.length > 0},
                "rowStyle": rowStyle
            });
        }
        let hasProxy = entries.some(e => e.status === "configured");
        let title = hasProxy ? "Proxy Configuration \u2014 proxy detected" : "Proxy Configuration \u2014 no proxy detected";
        return {"table": [{"headers": headers, "rows": rows, "title": title}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
