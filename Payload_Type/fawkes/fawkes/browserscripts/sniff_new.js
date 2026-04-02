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

        // Summary badge
        let summary = "Duration: " + data.duration +
            " | Packets: " + data.packet_count +
            " | Bytes: " + formatBytes(data.bytes_captured);

        if(data.errors && data.errors.length > 0){
            summary += " | Errors: " + data.errors.length;
        }

        let output = [];

        // Statistics card
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

        // Credentials table
        if(data.credentials && data.credentials.length > 0){
            let credHeaders = [
                {"plaintext": "Protocol", "type": "string", "width": 100},
                {"plaintext": "Source", "type": "string", "width": 180},
                {"plaintext": "Destination", "type": "string", "width": 180},
                {"plaintext": "Username", "type": "string", "fillWidth": true},
                {"plaintext": "Password/Detail", "type": "string", "fillWidth": true},
            ];
            let credRows = [];
            for(let c of data.credentials){
                let proto = c.protocol || "unknown";
                let protoStyle = {};
                let rowStyle = {};

                if(proto === "http-basic" || proto === "ftp"){
                    protoStyle = {"fontWeight": "bold", "color": "#f44336"};
                    rowStyle = {"backgroundColor": "rgba(244,67,54,0.08)"};
                } else if(proto === "ntlm"){
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
            output.push({
                "headers": credHeaders,
                "rows": credRows,
                "title": "Captured Credentials (" + data.credentials.length + ")",
            });
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

function formatBytes(bytes){
    if(bytes === 0) return "0 B";
    let k = 1024;
    let sizes = ["B", "KB", "MB", "GB"];
    let i = Math.floor(Math.log(bytes) / Math.log(k));
    if(i >= sizes.length) i = sizes.length - 1;
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}
