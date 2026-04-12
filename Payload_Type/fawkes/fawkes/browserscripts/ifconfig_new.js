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
        let headers = [
            {"plaintext": "Interface", "type": "string", "width": 120},
            {"plaintext": "Flags", "type": "string", "width": 180},
            {"plaintext": "MTU", "type": "number", "width": 70},
            {"plaintext": "MAC", "type": "string", "width": 150},
            {"plaintext": "IPv4", "type": "string", "width": 150},
            {"plaintext": "IPv6", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        let blocks = combined.split(/\n(?=\S)/);
        for(let b = 0; b < blocks.length; b++){
            let block = blocks[b].trim();
            if(!block) continue;
            let lines = block.split("\n");
            let ifName = "";
            let flags = "";
            let mtu = "";
            let mac = "";
            let ipv4 = [];
            let ipv6 = [];
            for(let i = 0; i < lines.length; i++){
                let line = lines[i].trim();
                let nameMatch = line.match(/^(\S+?):/);
                if(nameMatch && i === 0) ifName = nameMatch[1];
                let flagMatch = line.match(/flags=\S+\s*<([^>]*)>/);
                if(flagMatch) flags = flagMatch[1];
                let mtuMatch = line.match(/mtu\s+(\d+)/);
                if(mtuMatch) mtu = mtuMatch[1];
                let macMatch = line.match(/(?:ether|link\/ether)\s+([\da-fA-F:]+)/);
                if(macMatch) mac = macMatch[1];
                let ip4Match = line.match(/inet\s+([\d.]+)/);
                if(ip4Match) ipv4.push(ip4Match[1]);
                let ip6Match = line.match(/inet6\s+([\da-fA-F:]+)/);
                if(ip6Match) ipv6.push(ip6Match[1]);
            }
            if(!ifName) continue;
            let isUp = flags.includes("UP");
            rows.push({
                "Interface": {"plaintext": ifName, "cellStyle": {"fontWeight": "bold", "color": isUp ? "#2ecc71" : "#95a5a6"}},
                "Flags": {"plaintext": flags, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}},
                "MTU": {"plaintext": mtu, "cellStyle": {"fontFamily": "monospace"}},
                "MAC": {"plaintext": mac, "cellStyle": {"fontFamily": "monospace"}, "copyIcon": true},
                "IPv4": {"plaintext": ipv4.join(", "), "cellStyle": {"fontFamily": "monospace"}, "copyIcon": ipv4.length > 0},
                "IPv6": {"plaintext": ipv6.join(", "), "cellStyle": {"fontFamily": "monospace", "fontSize": "0.85em"}},
            });
        }
        if(rows.length === 0){
            return {"plaintext": combined};
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Network Interfaces (" + rows.length + ")"}]};
    } catch(error) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {"plaintext": combined};
    }
}
