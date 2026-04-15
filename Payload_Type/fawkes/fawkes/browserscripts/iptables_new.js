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
        let sections = [];
        let currentSection = null;
        let rules = [];
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(line.startsWith("=== ") || line.startsWith("--- ")){
                if(currentSection && rules.length > 0){
                    sections.push({title: currentSection, rules: rules});
                }
                currentSection = line.replace(/^[=-]+\s*/, "").replace(/\s*[=-]+$/, "");
                rules = [];
            } else if(line && !line.startsWith("Chain") && !line.startsWith("target") && currentSection){
                rules.push(line);
            }
        }
        if(currentSection && rules.length > 0){
            sections.push({title: currentSection, rules: rules});
        }
        if(sections.length === 0){
            return {"plaintext": combined};
        }
        let tables = [];
        for(let s = 0; s < sections.length; s++){
            let rows = [];
            for(let r = 0; r < sections[s].rules.length; r++){
                let rowStyle = {};
                let rule = sections[s].rules[r];
                if(rule.includes("DROP") || rule.includes("REJECT")){
                    rowStyle = {"backgroundColor": "rgba(255,0,0,0.08)"};
                } else if(rule.includes("ACCEPT")){
                    rowStyle = {"backgroundColor": "rgba(0,255,0,0.05)"};
                }
                rows.push({
                    "Rule": {"plaintext": rule},
                    "rowStyle": rowStyle
                });
            }
            tables.push({
                "headers": [{"plaintext": "Rule", "type": "string", "fillWidth": true}],
                "rows": rows,
                "title": sections[s].title + " (" + sections[s].rules.length + " rules)"
            });
        }
        return {"table": tables};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
