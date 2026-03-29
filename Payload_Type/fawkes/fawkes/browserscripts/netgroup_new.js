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
        let tables = [];
        // Detect output type
        let isGroupList = combined.includes("Domain Groups");
        let isMemberList = combined.includes("Members of");
        let isUserGroups = combined.includes("Group Memberships for");
        let isPrivileged = combined.includes("Privileged Group Enumeration");
        if(isGroupList){
            // Parse: "Group Name          [Type]  Members: N  — Description"
            let entries = [];
            for(let i = 0; i < lines.length; i++){
                let line = lines[i].trim();
                if(line === "" || line.match(/^={10,}/) || line.startsWith("Domain Groups")) continue;
                let match = line.match(/^(.+?)\s+\[(.+?)\]\s+Members:\s+(\d+)(.*)/);
                if(match){
                    let desc = match[4].replace(/^\s*\u2014\s*/, "").trim();
                    entries.push({name: match[1].trim(), type: match[2], members: parseInt(match[3]), desc: desc});
                }
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Group", "type": "string", "width": 220},
                    {"plaintext": "Type", "type": "string", "width": 160},
                    {"plaintext": "Members", "type": "number", "width": 90},
                    {"plaintext": "Description", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    rows.push({
                        "Group": {"plaintext": e.name, "cellStyle": {"fontWeight": "bold"}, "copyIcon": true},
                        "Type": {"plaintext": e.type, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                        "Members": {"plaintext": String(e.members), "cellStyle": e.members > 10 ? {"fontWeight": "bold"} : {}},
                        "Description": {"plaintext": e.desc}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "Domain Groups \u2014 " + entries.length});
            }
        }
        if(isMemberList){
            let entries = [];
            let memberType = "";
            for(let i = 0; i < lines.length; i++){
                let line = lines[i].trim();
                if(line.startsWith("Users (")) memberType = "User";
                else if(line.startsWith("Computers (")) memberType = "Computer";
                else if(line.startsWith("Nested Groups (")) memberType = "Group";
                let memMatch = line.match(/^-\s+(.*)/);
                if(memMatch && memberType){
                    entries.push({name: memMatch[1], type: memberType});
                }
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Member", "type": "string", "fillWidth": true},
                    {"plaintext": "Type", "type": "string", "width": 120}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    rows.push({
                        "Member": {"plaintext": e.name, "copyIcon": true, "cellStyle": {"fontWeight": "bold"}},
                        "Type": {"plaintext": e.type}
                    });
                }
                let titleMatch = combined.match(/Members of "(.+?)"/);
                let title = titleMatch ? "Members of " + titleMatch[1] + " \u2014 " + entries.length : "Group Members \u2014 " + entries.length;
                tables.push({"headers": headers, "rows": rows, "title": title});
            }
        }
        if(isUserGroups){
            let entries = [];
            let isPriv = false;
            for(let i = 0; i < lines.length; i++){
                let line = lines[i].trim();
                if(line.includes("PRIVILEGED Groups")) isPriv = true;
                else if(line.startsWith("Other Groups")) isPriv = false;
                let privMatch = line.match(/^\*\s+(.+?)\s+\[(.+?)\]/);
                if(privMatch){
                    entries.push({name: privMatch[1], type: privMatch[2], privileged: true});
                    continue;
                }
                let normMatch = line.match(/^-\s+(.+?)\s+\[(.+?)\]/);
                if(normMatch){
                    entries.push({name: normMatch[1], type: normMatch[2], privileged: false});
                }
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Group", "type": "string", "width": 250},
                    {"plaintext": "Type", "type": "string", "width": 180},
                    {"plaintext": "Privileged", "type": "string", "width": 100}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    let rowStyle = e.privileged ? {"backgroundColor": "rgba(255,0,0,0.08)"} : {};
                    rows.push({
                        "Group": {"plaintext": e.name, "cellStyle": e.privileged ? {"fontWeight": "bold", "color": "#d94f00"} : {"fontWeight": "bold"}, "copyIcon": true},
                        "Type": {"plaintext": e.type, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}},
                        "Privileged": {"plaintext": e.privileged ? "Yes" : "", "cellStyle": e.privileged ? {"color": "#d94f00", "fontWeight": "bold"} : {}},
                        "rowStyle": rowStyle
                    });
                }
                let userMatch = combined.match(/Group Memberships for "(.+?)"/);
                let title = userMatch ? "Groups for " + userMatch[1] : "Group Memberships";
                tables.push({"headers": headers, "rows": rows, "title": title + " \u2014 " + entries.length});
            }
        }
        if(isPrivileged){
            let entries = [];
            let currentGroup = "";
            for(let i = 0; i < lines.length; i++){
                let line = lines[i].trim();
                let groupMatch = line.match(/^(.+?)\s+\((\d+)\s+members?\)/);
                if(groupMatch){
                    currentGroup = groupMatch[1];
                    continue;
                }
                let memMatch = line.match(/^-\s+(.+?)\s+\((\w+)\)/);
                if(memMatch && currentGroup){
                    entries.push({group: currentGroup, member: memMatch[1], type: memMatch[2]});
                }
            }
            if(entries.length > 0){
                let headers = [
                    {"plaintext": "Privileged Group", "type": "string", "width": 200},
                    {"plaintext": "Member", "type": "string", "fillWidth": true},
                    {"plaintext": "Type", "type": "string", "width": 100}
                ];
                let rows = [];
                for(let j = 0; j < entries.length; j++){
                    let e = entries[j];
                    rows.push({
                        "Privileged Group": {"plaintext": e.group, "cellStyle": {"fontWeight": "bold", "color": "#d94f00"}},
                        "Member": {"plaintext": e.member, "copyIcon": true},
                        "Type": {"plaintext": e.type},
                        "rowStyle": {"backgroundColor": "rgba(255,0,0,0.06)"}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "Privileged Group Members \u2014 " + entries.length + " accounts"});
            }
        }
        if(tables.length === 0){
            return {"plaintext": combined};
        }
        return {"table": tables};
    } catch(error){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
}
