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
        let psoName = "";
        let appliesTo = [];
        let inAppliesTo = false;
        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let trimmed = line.trim();
            if(trimmed === "" || trimmed.match(/^-{10,}/)) continue;
            // Section headers
            let secMatch = trimmed.match(/^\[\*\]\s+(.*)/);
            if(secMatch){
                currentSection = secMatch[1];
                inAppliesTo = false;
                continue;
            }
            // PSO name
            let psoMatch = trimmed.match(/^\[PSO\]\s+(.*)/);
            if(psoMatch){
                psoName = psoMatch[1];
                inAppliesTo = false;
                continue;
            }
            // Spray recommendation
            let sprayMatch = trimmed.match(/^\[\+\]\s+(.*)/);
            if(sprayMatch){
                entries.push({section: currentSection, pso: psoName, setting: sprayMatch[1], value: "", isRecommendation: true});
                continue;
            }
            // Applies To section
            if(trimmed === "Applies To:"){
                inAppliesTo = true;
                continue;
            }
            if(inAppliesTo){
                let applyMatch = trimmed.match(/^-\s+(.*)/);
                if(applyMatch){
                    entries.push({section: currentSection, pso: psoName, setting: "Applies To", value: applyMatch[1], isAppliesTo: true});
                    continue;
                } else {
                    inAppliesTo = false;
                }
            }
            // Key-value pairs: "    Setting Name:    Value"
            let kvMatch = trimmed.match(/^(.+?):\s+(.*)/);
            if(kvMatch){
                entries.push({section: currentSection, pso: psoName, setting: kvMatch[1].trim(), value: kvMatch[2].trim()});
            }
        }
        if(entries.length === 0){
            return {"plaintext": combined};
        }
        let headers = [
            {"plaintext": "Section", "type": "string", "width": 180},
            {"plaintext": "Setting", "type": "string", "width": 220},
            {"plaintext": "Value", "type": "string", "fillWidth": true}
        ];
        let rows = [];
        for(let j = 0; j < entries.length; j++){
            let e = entries[j];
            let section = e.pso ? "[PSO] " + e.pso : e.section;
            let rowStyle = {};
            let valStyle = {};
            if(e.isRecommendation){
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.1)"};
                valStyle = {"color": "#4caf50", "fontWeight": "bold"};
            }
            if(e.isAppliesTo){
                valStyle = {"fontFamily": "monospace", "fontSize": "0.9em"};
            }
            // Highlight important values
            if(e.setting.includes("Complexity") && e.value.includes("No Complexity")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                valStyle = {"color": "#ff8c00", "fontWeight": "bold"};
            }
            if(e.setting.includes("Lockout Threshold") && e.value.startsWith("0")){
                rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                valStyle = {"color": "#ff8c00", "fontWeight": "bold"};
            }
            if(e.setting.includes("Minimum Password Length")){
                let lenMatch = e.value.match(/^(\d+)/);
                if(lenMatch && parseInt(lenMatch[1]) < 8){
                    rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                    valStyle = {"color": "#ff8c00", "fontWeight": "bold"};
                }
            }
            rows.push({
                "Section": {"plaintext": section},
                "Setting": {"plaintext": e.isRecommendation ? "\u2192 " + e.setting : e.setting, "cellStyle": e.isRecommendation ? {"fontWeight": "bold"} : {}},
                "Value": {"plaintext": e.value, "cellStyle": valStyle, "copyIcon": e.value.length > 0},
                "rowStyle": rowStyle
            });
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Domain Policy"}]};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
