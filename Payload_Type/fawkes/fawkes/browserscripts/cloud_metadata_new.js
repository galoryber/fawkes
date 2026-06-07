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

        let parsed = null;
        try {
            parsed = JSON.parse(combined);
        } catch(e) {}

        if(parsed !== null && isCloudStorageListing(parsed)){
            return renderCloudStorage(parsed);
        }

        return renderPlaintext(combined);
    } catch(error) {
        let combined = "";
        for(let i = 0; i < responses.length; i++){
            combined += responses[i];
        }
        return {"plaintext": combined};
    }
}

function isCloudStorageListing(data){
    if(Array.isArray(data)){
        return data.length > 0 && data[0].action === "cloud-storage";
    }
    return data.action === "cloud-storage";
}

function renderCloudStorage(data){
    let listings = Array.isArray(data) ? data : [data];

    let headers = [
        {"plaintext": "Provider", "type": "string", "width": 90},
        {"plaintext": "Type", "type": "string", "width": 80},
        {"plaintext": "Name", "type": "string", "width": 250},
        {"plaintext": "Details", "type": "string", "fillWidth": true},
        {"plaintext": "Size", "type": "size", "width": 100},
    ];

    let rows = [];
    let providerIcons = {"aws": "☁ AWS", "azure": "☁ Azure", "gcp": "☁ GCP"};
    let providerColors = {
        "aws": "rgba(255,153,0,0.12)",
        "azure": "rgba(0,120,212,0.1)",
        "gcp": "rgba(66,133,244,0.1)",
    };

    for(let listing of listings){
        let provider = providerIcons[listing.provider] || listing.provider;
        let bgColor = providerColors[listing.provider] || "";

        if(listing.error){
            rows.push({
                "Provider": {"plaintext": provider},
                "Type": {"plaintext": "Error"},
                "Name": {"plaintext": listing.error},
                "Details": {"plaintext": ""},
                "Size": {"plaintext": ""},
                "rowStyle": {"backgroundColor": "rgba(255,0,0,0.08)"},
            });
            continue;
        }

        let details = [];
        if(listing.role) details.push("Role: " + listing.role);
        if(listing.project) details.push("Project: " + listing.project);
        if(listing.account) details.push("Account: " + listing.account);
        if(listing.region) details.push("Region: " + listing.region);

        rows.push({
            "Provider": {"plaintext": provider},
            "Type": {"plaintext": "Host"},
            "Name": {"plaintext": listing.host, "cellStyle": {"fontWeight": "bold"}},
            "Details": {"plaintext": details.join(" | ")},
            "Size": {"plaintext": ""},
            "rowStyle": {"backgroundColor": "rgba(128,128,128,0.08)"},
        });

        for(let bucket of (listing.buckets || [])){
            let bucketDetails = [];
            if(bucket.location) bucketDetails.push("Location: " + bucket.location);
            if(bucket.storage_class) bucketDetails.push("Class: " + bucket.storage_class);
            if(bucket.created) bucketDetails.push("Created: " + bucket.created);

            rows.push({
                "Provider": {"plaintext": provider},
                "Type": {"plaintext": "📁 Bucket"},
                "Name": {"plaintext": bucket.uri || bucket.name, "cellStyle": {"fontWeight": "bold"}, "copyIcon": true},
                "Details": {"plaintext": bucketDetails.join(" | ")},
                "Size": {"plaintext": ""},
                "rowStyle": {"backgroundColor": bgColor},
            });

            for(let obj of (bucket.objects || [])){
                rows.push({
                    "Provider": {"plaintext": ""},
                    "Type": {"plaintext": "📄 Object"},
                    "Name": {"plaintext": "  " + obj.name, "copyIcon": true},
                    "Details": {"plaintext": ""},
                    "Size": {"plaintext": obj.size > 0 ? formatSize(obj.size) : "", "copyIcon": obj.size > 0},
                    "rowStyle": {},
                });
            }
        }
    }

    let totalBuckets = 0;
    let providers = new Set();
    for(let l of listings){
        if(!l.error){
            totalBuckets += (l.buckets || []).length;
            providers.add(l.provider);
        }
    }

    let title = "Cloud Storage — " + Array.from(providers).join(", ") +
        " (" + totalBuckets + " bucket" + (totalBuckets !== 1 ? "s" : "") + ")";

    return {
        "table": [{
            "headers": headers,
            "rows": rows,
            "title": title,
        }]
    };
}

function formatSize(bytes){
    if(bytes === 0) return "0 B";
    let units = ["B", "KB", "MB", "GB", "TB"];
    let i = Math.floor(Math.log(bytes) / Math.log(1024));
    if(i >= units.length) i = units.length - 1;
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

function renderPlaintext(combined){
    let lines = combined.split("\n");
    let kvEntries = [];
    let providerColors = {
        "AWS": "rgba(255,153,0,0.12)",
        "Azure": "rgba(0,120,212,0.1)",
        "GCP": "rgba(66,133,244,0.1)",
        "DigitalOcean": "rgba(0,105,225,0.1)",
    };
    let sensitiveKeys = new Set(["AccessKeyId", "SecretAccessKey", "Token", "Access Token", "Session Token"]);
    let currentSection = "";
    let currentProvider = "";

    for(let i = 0; i < lines.length; i++){
        let line = lines[i];
        let sectionMatch = line.match(/^===\s+(.+?)\s+===$/);
        if(sectionMatch){
            currentSection = sectionMatch[1];
            continue;
        }
        let providerMatch = line.match(/^\[([+*\-])\]\s+(AWS|Azure|GCP|DigitalOcean)\b/i);
        if(providerMatch){
            currentProvider = providerMatch[2];
            let desc = line.replace(/^\[[+*\-]\]\s+/, "").trim();
            kvEntries.push({
                provider: currentProvider, key: "Status", value: desc,
                section: currentSection, isSensitive: false, isHeader: true,
            });
            continue;
        }
        let kvMatch = line.match(/^\s{2,}(\S[^:]*?):\s+(.+)/);
        if(kvMatch){
            let key = kvMatch[1].trim();
            let value = kvMatch[2].trim();
            kvEntries.push({
                provider: currentProvider || "Unknown", key: key, value: value,
                section: currentSection, isSensitive: sensitiveKeys.has(key), isHeader: false,
            });
            continue;
        }
        let statusMatch = line.match(/^\[([+*\-])\]\s+(.+)/);
        if(statusMatch){
            kvEntries.push({
                provider: currentProvider || "General", key: "Info",
                value: statusMatch[2].trim(), section: currentSection,
                isSensitive: false, isHeader: true,
            });
        }
    }

    if(kvEntries.length === 0){
        return {"plaintext": combined};
    }

    let headers = [
        {"plaintext": "Provider", "type": "string", "width": 120},
        {"plaintext": "Key", "type": "string", "width": 180},
        {"plaintext": "Value", "type": "string", "fillWidth": true},
        {"plaintext": "Section", "type": "string", "width": 180},
    ];
    let rows = [];
    let providersFound = new Set();

    for(let entry of kvEntries){
        if(!entry.isHeader) providersFound.add(entry.provider);
        let rowStyle = {};
        let bgColor = providerColors[entry.provider];
        if(entry.isSensitive){
            rowStyle = {"backgroundColor": "rgba(255,87,34,0.15)"};
        } else if(entry.isHeader){
            rowStyle = {"backgroundColor": "rgba(128,128,128,0.08)"};
        } else if(bgColor){
            rowStyle = {"backgroundColor": bgColor};
        }
        rows.push({
            "Provider": {"plaintext": entry.provider},
            "Key": {"plaintext": entry.key, "cellStyle": entry.isSensitive ? {"fontWeight": "bold"} : {}},
            "Value": {"plaintext": entry.value, "copyIcon": entry.isSensitive || !entry.isHeader},
            "Section": {"plaintext": entry.section},
            "rowStyle": rowStyle,
        });
    }

    let providerList = Array.from(providersFound);
    let title = "Cloud Metadata";
    if(providerList.length > 0) title += " — " + providerList.join(", ");
    title += " (" + kvEntries.length + " entries)";

    return {
        "table": [{
            "headers": headers,
            "rows": rows,
            "title": title,
        }]
    };
}
