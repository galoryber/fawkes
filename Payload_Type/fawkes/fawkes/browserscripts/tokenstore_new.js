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
            return {"plaintext": combined};
        }

        // Detect format: identity history (has "operation" field) vs token store (has "token_id")
        if(data[0].operation !== undefined){
            return renderIdentityHistory(data);
        }

        // Token store format
        let headers = [
            {"plaintext": "Token ID", "type": "number", "width": 100},
            {"plaintext": "PID", "type": "number", "width": 90},
            {"plaintext": "User", "type": "string", "fillWidth": true},
            {"plaintext": "Type", "type": "string", "width": 150},
            {"plaintext": "Impersonation Level", "type": "string", "width": 200},
        ];
        let rows = [];
        for(let j = 0; j < data.length; j++){
            let e = data[j];
            let user = e.user || "N/A";
            let rowStyle = {};
            let lowerUser = user.toLowerCase();
            if(lowerUser === "system" || lowerUser === "nt authority\\system" || lowerUser === "nt authority\\local service" || lowerUser === "nt authority\\network service"){
                rowStyle = {"backgroundColor": "rgba(255,0,0,0.15)"};
            }
            rows.push({
                "Token ID": {"plaintext": e.token_id, "copyIcon": true},
                "PID": {"plaintext": e.pid, "copyIcon": true},
                "User": {"plaintext": user, "copyIcon": true},
                "Type": {"plaintext": e.type || "N/A"},
                "Impersonation Level": {"plaintext": e.impersonation_level || "N/A"},
                "rowStyle": rowStyle,
            });
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Token Store (" + data.length + " tokens)",
            }]
        };
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}

function renderIdentityHistory(events){
    let levelColors = {
        "SYSTEM": "rgba(255,0,0,0.15)",
        "admin": "rgba(255,165,0,0.15)",
        "user": "rgba(100,149,237,0.10)",
    };
    let opLabels = {
        "stealtoken": "\u{1F50D} steal-token",
        "maketoken": "\u{1F511} make-token",
        "rev2self": "\u{21A9}\u{FE0F} rev2self",
        "getsystem": "\u{26A1} getsystem",
        "token-store-use": "\u{1F4E6} token-store use",
    };

    let headers = [
        {"plaintext": "#", "type": "number", "width": 50},
        {"plaintext": "Time", "type": "string", "width": 180},
        {"plaintext": "Operation", "type": "string", "width": 180},
        {"plaintext": "From", "type": "string", "fillWidth": true},
        {"plaintext": "To", "type": "string", "fillWidth": true},
        {"plaintext": "Level", "type": "string", "width": 100},
        {"plaintext": "Detail", "type": "string", "width": 200},
    ];
    let rows = [];
    for(let i = 0; i < events.length; i++){
        let e = events[i];
        let level = e.level || "user";
        let rowStyle = {};
        if(levelColors[level]){
            rowStyle = {"backgroundColor": levelColors[level]};
        }
        let opDisplay = opLabels[e.operation] || e.operation;
        rows.push({
            "#": {"plaintext": i + 1},
            "Time": {"plaintext": e.timestamp || ""},
            "Operation": {"plaintext": opDisplay},
            "From": {"plaintext": e.from_user || "(process token)", "copyIcon": true},
            "To": {"plaintext": e.to_user || "", "copyIcon": true},
            "Level": {"plaintext": level},
            "Detail": {"plaintext": e.detail || ""},
            "rowStyle": rowStyle,
        });
    }
    return {
        "table": [{
            "headers": headers,
            "rows": rows,
            "title": "Identity Chain Timeline (" + events.length + " transitions)",
        }]
    };
}
