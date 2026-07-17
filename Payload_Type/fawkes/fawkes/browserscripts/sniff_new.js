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
        combined = combined.trim();

        let data = JSON.parse(combined);

        if(data.relays !== undefined || data.operation !== undefined){
            return renderLDAPRelay(data);
        }

        let output = [];

        let statHeaders = [
            {"plaintext": "Metric", "type": "string", "width": 200},
            {"plaintext": "Value", "type": "string", "fillWidth": true},
        ];
        let statRows = [
            {"Metric": {"plaintext": "Duration"}, "Value": {"plaintext": data.duration || "N/A"}},
            {"Metric": {"plaintext": "Packets Captured"}, "Value": {"plaintext": String(data.packet_count || 0)}},
            {"Metric": {"plaintext": "Bytes Captured"}, "Value": {"plaintext": formatBytes(data.bytes_captured || 0)}},
        ];
        if(data.errors && data.errors.length > 0){
            for(let e of data.errors){
                statRows.push({
                    "Metric": {"plaintext": "Error", "cellStyle": {"color": "#f44336"}},
                    "Value": {"plaintext": e, "cellStyle": {"color": "#f44336"}},
                });
            }
        }
        output.push({"headers": statHeaders, "rows": statRows, "title": "Capture Statistics"});

        if(data.credentials && data.credentials.length > 0){
            output.push(renderCredentialsTable(data.credentials));
        } else {
            output.push({
                "headers": [{"plaintext": "Result", "type": "string", "fillWidth": true}],
                "rows": [{"Result": {"plaintext": "No credentials captured during the sniff period.", "cellStyle": {"fontStyle": "italic"}}}],
                "title": "Credentials",
            });
        }

        return {"table": output};
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}

function renderLDAPRelay(data){
    let output = [];

    let statHeaders = [
        {"plaintext": "Metric", "type": "string", "width": 200},
        {"plaintext": "Value", "type": "string", "fillWidth": true},
    ];
    let isLDAP = !!data.operation;
    let relayType = isLDAP ? "LDAP" : "SMB";
    let defaultPort = isLDAP ? 389 : 445;
    let statRows = [
        {"Metric": {"plaintext": "Duration"}, "Value": {"plaintext": data.duration || "N/A"}},
        {"Metric": {"plaintext": "Type"}, "Value": {"plaintext": relayType + " Relay", "cellStyle": {"fontWeight": "bold"}}},
    ];
    if(isLDAP){
        statRows.push({"Metric": {"plaintext": "Operation"}, "Value": {"plaintext": data.operation.toUpperCase(), "cellStyle": {"fontWeight": "bold"}}});
    }
    statRows.push(
        {"Metric": {"plaintext": "Target"}, "Value": {"plaintext": (data.target || "") + ":" + (data.target_port || defaultPort)}},
        {"Metric": {"plaintext": "Listen Port"}, "Value": {"plaintext": String(data.listen_port || 80)}},
        {"Metric": {"plaintext": "Relays"}, "Value": {"plaintext": String((data.relays || []).length)}}
    );
    if(data.errors && data.errors.length > 0){
        for(let e of data.errors){
            statRows.push({
                "Metric": {"plaintext": "Error", "cellStyle": {"color": "#f44336"}},
                "Value": {"plaintext": e, "cellStyle": {"color": "#f44336"}},
            });
        }
    }
    output.push({"headers": statHeaders, "rows": statRows, "title": relayType + " Relay Summary"});

    if(data.relays && data.relays.length > 0){
        let relayHeaders = [
            {"plaintext": "Status", "type": "string", "width": 120},
            {"plaintext": "Victim", "type": "string", "width": 140},
            {"plaintext": "Identity", "type": "string", "width": 250},
            {"plaintext": "Operation Result", "type": "string", "fillWidth": true},
        ];
        let relayRows = [];
        for(let r of data.relays){
            let statusStyle = {};
            let rowStyle = {};
            let statusText = (r.status || "unknown").toUpperCase();

            if(r.success){
                statusStyle = {"fontWeight": "bold", "color": "#4caf50"};
                rowStyle = {"backgroundColor": "rgba(76,175,80,0.08)"};
            } else if(r.status === "logon_failure"){
                statusStyle = {"fontWeight": "bold", "color": "#ff9800"};
                rowStyle = {"backgroundColor": "rgba(255,152,0,0.08)"};
            } else {
                statusStyle = {"fontWeight": "bold", "color": "#f44336"};
                rowStyle = {"backgroundColor": "rgba(244,67,54,0.08)"};
            }

            let identity = "";
            if(r.domain) identity = r.domain + "\\";
            identity += r.username || "unknown";

            relayRows.push({
                "Status": {"plaintext": statusText, "cellStyle": statusStyle},
                "Victim": {"plaintext": r.victim_ip || "", "copyIcon": true},
                "Identity": {"plaintext": identity, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                "Operation Result": {"plaintext": r.op_result || r.detail || "", "copyIcon": true},
                "rowStyle": rowStyle,
            });
        }
        output.push({"headers": relayHeaders, "rows": relayRows, "title": "Relay Results (" + data.relays.length + ")"});

        let hasHashcat = data.relays.some(function(r){ return r.hashcat; });
        if(hasHashcat){
            let hashHeaders = [
                {"plaintext": "Identity", "type": "string", "width": 250},
                {"plaintext": "NTLMv2 Hash (hashcat -m 5600)", "type": "string", "fillWidth": true},
            ];
            let hashRows = [];
            for(let r of data.relays){
                if(r.hashcat){
                    let identity = "";
                    if(r.domain) identity = r.domain + "\\";
                    identity += r.username || "unknown";
                    hashRows.push({
                        "Identity": {"plaintext": identity, "cellStyle": {"fontWeight": "bold"}},
                        "NTLMv2 Hash (hashcat -m 5600)": {"plaintext": r.hashcat, "copyIcon": true},
                    });
                }
            }
            output.push({"headers": hashHeaders, "rows": hashRows, "title": "Captured Hashes"});
        }
    }

    if(data.credentials && data.credentials.length > 0){
        output.push(renderCredentialsTable(data.credentials));
    }

    return {"table": output};
}

function renderCredentialsTable(credentials){
    let credHeaders = [
        {"plaintext": "Protocol", "type": "string", "width": 100},
        {"plaintext": "Source", "type": "string", "width": 180},
        {"plaintext": "Destination", "type": "string", "width": 180},
        {"plaintext": "Username", "type": "string", "fillWidth": true},
        {"plaintext": "Password/Detail", "type": "string", "fillWidth": true},
    ];
    let credRows = [];
    for(let c of credentials){
        let proto = c.protocol || "unknown";
        let protoStyle = {};
        let rowStyle = {};

        if(proto === "http-basic" || proto === "ftp"){
            protoStyle = {"fontWeight": "bold", "color": "#f44336"};
            rowStyle = {"backgroundColor": "rgba(244,67,54,0.08)"};
        } else if(proto === "ntlm" || proto.indexOf("ntlmv2") >= 0){
            protoStyle = {"fontWeight": "bold", "color": "#ff9800"};
            rowStyle = {"backgroundColor": "rgba(255,152,0,0.08)"};
        }

        let src = c.src_ip || "";
        if(c.src_port) src += ":" + c.src_port;
        let dst = c.dst_ip || "";
        if(c.dst_port) dst += ":" + c.dst_port;

        let secret = c.password || c.detail || "";

        credRows.push({
            "Protocol": {"plaintext": proto.toUpperCase(), "cellStyle": protoStyle},
            "Source": {"plaintext": src, "copyIcon": true},
            "Destination": {"plaintext": dst, "copyIcon": true},
            "Username": {"plaintext": c.username || "", "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
            "Password/Detail": {"plaintext": secret, "copyIcon": true},
            "rowStyle": rowStyle,
        });
    }
    return {
        "headers": credHeaders,
        "rows": credRows,
        "title": "Captured Credentials (" + credentials.length + ")",
    };
}

function formatBytes(bytes){
    if(bytes === 0) return "0 B";
    let k = 1024;
    let sizes = ["B", "KB", "MB", "GB"];
    let i = Math.floor(Math.log(bytes) / Math.log(k));
    if(i >= sizes.length) i = sizes.length - 1;
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}
