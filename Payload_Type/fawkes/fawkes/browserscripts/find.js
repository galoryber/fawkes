function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }
    if(responses.length === 0){
        return {"plaintext": "No response yet from agent..."};
    }

    const combined = responses.reduce((prev, cur) => prev + cur, "");

    // Check for "No files matching" or no results
    if(combined.includes("No files matching")){
        return {"plaintext": combined};
    }

    // Parse the header line: "Found N match(es) for 'pattern' in /path:"
    let headerMatch = combined.match(/Found (\d+) match\(es\) for '([^']+)' in ([^:]+):/);
    if(!headerMatch){
        return {"plaintext": combined};
    }

    let matchCount = headerMatch[1];
    let pattern = headerMatch[2];
    let searchPath = headerMatch[3];

    // Parse result lines: "%-12s %-16s %s" = "<size>  <date>  <path>"
    let lines = combined.split("\n");
    let entries = [];

    for(let i = 0; i < lines.length; i++){
        let line = lines[i].trim();
        if(line === "" || line.startsWith("Found ") || line.startsWith("(results") || line.includes("inaccessible")){
            continue;
        }

        // Split into fields and look for date pattern YYYY-MM-DD HH:MM
        let parts = line.split(/\s+/);
        if(parts.length < 3){
            continue;
        }

        // Find the date field (YYYY-MM-DD)
        let dateIdx = -1;
        for(let j = 0; j < parts.length; j++){
            if(parts[j].match(/^\d{4}-\d{2}-\d{2}$/)){
                dateIdx = j;
                break;
            }
        }
        if(dateIdx < 0 || dateIdx + 2 >= parts.length){
            continue;
        }

        // Size is everything before the date
        let sizeStr = parts.slice(0, dateIdx).join(" ");
        let dateStr = parts[dateIdx] + " " + parts[dateIdx + 1];
        // Path is everything after the date+time (usually one field, but could have spaces)
        let filePath = parts.slice(dateIdx + 2).join(" ");
        let isDir = (sizeStr === "<DIR>");

        // Extract just the filename from the path
        let fileName = filePath;
        let lastSep = Math.max(filePath.lastIndexOf("/"), filePath.lastIndexOf("\\"));
        if(lastSep >= 0){
            fileName = filePath.substring(lastSep + 1);
        }

        entries.push({
            name: fileName,
            fullPath: filePath,
            size: sizeStr,
            date: dateStr,
            isDir: isDir,
        });
    }

    if(entries.length === 0){
        return {"plaintext": combined};
    }

    // Build sortable table
    let formattedResponse = {
        headers: [
            {
                plaintext: "actions",
                type: "button",
                cellStyle: {},
                width: 100,
                disableSort: true,
            },
            {
                plaintext: "type",
                type: "string",
                width: 60,
                cellStyle: {},
            },
            {
                plaintext: "name",
                type: "string",
                fillWidth: true,
                cellStyle: {},
            },
            {
                plaintext: "path",
                type: "string",
                fillWidth: true,
                cellStyle: {},
            },
            {
                plaintext: "size",
                type: "string",
                width: 100,
                cellStyle: {},
            },
            {
                plaintext: "modified",
                type: "string",
                width: 150,
                cellStyle: {},
            },
        ],
        title: "Found " + matchCount + " result(s) for '" + pattern + "' in " + searchPath,
        rows: [],
    };

    for(let i = 0; i < entries.length; i++){
        let entry = entries[i];
        let icon = entry.isDir ? "openFolder" : "";
        let iconColor = entry.isDir ? "rgb(241,226,0)" : "";
        let typeLabel = entry.isDir ? "DIR" : "FILE";

        // Sub-task: cat for files, ls for directories
        let actionButton;
        if(entry.isDir){
            actionButton = {
                name: "ls",
                type: "task",
                ui_feature: "file_browser:list",
                startIcon: "list",
                parameters: {
                    full_path: entry.fullPath,
                },
            };
        } else {
            actionButton = {
                name: "cat",
                type: "task",
                ui_feature: "cat",
                startIcon: "visibility",
                parameters: entry.fullPath,
            };
        }

        formattedResponse.rows.push({
            rowStyle: entry.isDir ? {fontWeight: "bold"} : {},
            actions: {
                button: actionButton,
                cellStyle: {},
            },
            type: {
                plaintext: typeLabel,
                cellStyle: entry.isDir ? {color: "rgb(241,226,0)"} : {},
            },
            name: {
                plaintext: entry.name,
                cellStyle: {},
                startIcon: icon,
                startIconColor: iconColor,
            },
            path: {
                plaintext: entry.fullPath,
                cellStyle: {fontSize: "0.85em", opacity: "0.8"},
            },
            size: {
                plaintext: entry.size,
                cellStyle: {},
            },
            modified: {
                plaintext: entry.date,
                cellStyle: {},
            },
        });
    }

    // Add footer notes
    let footer = "";
    if(combined.includes("results truncated")){
        footer += "(results truncated at 500) ";
    }
    let inaccessMatch = combined.match(/(\d+) path\(s\) inaccessible/);
    if(inaccessMatch){
        footer += inaccessMatch[1] + " path(s) inaccessible";
    }

    if(footer){
        return {table: [formattedResponse], plaintext: footer};
    }
    return {table: [formattedResponse]};
}
