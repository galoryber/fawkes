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
            return {"plaintext": "No mitigation policies found"};
        }
        // Group by category if the field exists
        let categories = {};
        let hasCategory = false;
        for(let i = 0; i < data.length; i++){
            let cat = data[i].category || "General";
            if(data[i].category) hasCategory = true;
            if(!categories[cat]) categories[cat] = [];
            categories[cat].push(data[i]);
        }
        let tables = [];
        let catNames = Object.keys(categories).sort();
        let totalEnabled = 0;
        let totalPolicies = data.length;
        for(let c = 0; c < catNames.length; c++){
            let catName = catNames[c];
            let items = categories[catName];
            let headers = [
                {"plaintext": "Policy", "type": "string", "fillWidth": true},
                {"plaintext": "Enabled", "type": "string", "width": 100},
                {"plaintext": "Value", "type": "string", "width": 200},
            ];
            let rows = [];
            for(let j = 0; j < items.length; j++){
                let e = items[j];
                let enabled = e.enabled === true || e.enabled === "true" || e.enabled === "True";
                if(enabled) totalEnabled++;
                let enabledText = enabled ? "Yes" : "No";
                let enabledStyle = enabled
                    ? {"color": "#4caf50", "fontWeight": "bold"}
                    : {"color": "#f44336"};
                let rowStyle = enabled
                    ? {"backgroundColor": "rgba(76,175,80,0.06)"}
                    : {};
                rows.push({
                    "Policy": {"plaintext": e.policy || "", "copyIcon": true},
                    "Enabled": {"plaintext": enabledText, "cellStyle": enabledStyle},
                    "Value": {"plaintext": e.value !== undefined ? String(e.value) : "", "cellStyle": {"fontFamily": "monospace"}},
                    "rowStyle": rowStyle,
                });
            }
            let title = hasCategory
                ? catName + " (" + items.length + " policies)"
                : "Process Mitigation Policies (" + totalPolicies + " policies)";
            tables.push({"headers": headers, "rows": rows, "title": title});
        }
        // If grouped, add a summary title to the first table
        if(hasCategory && tables.length > 0){
            tables[0].title = catNames[0] + " (" + categories[catNames[0]].length + " policies) \u2014 " + totalEnabled + "/" + totalPolicies + " enabled overall";
        }
        return {"table": tables};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
