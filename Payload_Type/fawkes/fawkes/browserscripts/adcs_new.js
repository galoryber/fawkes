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
        // Detect sections
        let hasCAs = combined.includes("Certificate Authorities");
        let hasTemplates = combined.includes("Certificate Templates");
        let hasFindings = combined.includes("Vulnerability Assessment") || combined.includes("[!]");
        let hasESC6 = combined.includes("ESC6 Check");
        // Parse CAs
        if(hasCAs){
            let cas = [];
            let currentCA = null;
            let inCA = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.startsWith("Certificate Templates")) break;
                let caMatch = trimmed.match(/^\[CA\s*\d*\]\s+(.*)/);
                if(caMatch){
                    if(currentCA) cas.push(currentCA);
                    currentCA = {name: caMatch[1], dns: "", dn: "", templates: []};
                    inCA = true;
                    continue;
                }
                if(inCA && currentCA){
                    let dnsMatch = trimmed.match(/^DNS Name:\s+(.*)/);
                    if(dnsMatch) currentCA.dns = dnsMatch[1];
                    let dnMatch = trimmed.match(/^CA DN:\s+(.*)/);
                    if(dnMatch) currentCA.dn = dnMatch[1];
                    let tplMatch = trimmed.match(/^-\s+(.*)/);
                    if(tplMatch) currentCA.templates.push(tplMatch[1]);
                }
            }
            if(currentCA) cas.push(currentCA);
            if(cas.length > 0){
                let headers = [
                    {"plaintext": "CA Name", "type": "string", "width": 200},
                    {"plaintext": "DNS", "type": "string", "width": 200},
                    {"plaintext": "Templates", "type": "number", "width": 90},
                    {"plaintext": "DN", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let j = 0; j < cas.length; j++){
                    let ca = cas[j];
                    rows.push({
                        "CA Name": {"plaintext": ca.name, "cellStyle": {"fontWeight": "bold"}},
                        "DNS": {"plaintext": ca.dns, "copyIcon": true},
                        "Templates": {"plaintext": String(ca.templates.length)},
                        "DN": {"plaintext": ca.dn, "cellStyle": {"fontFamily": "monospace", "fontSize": "0.9em"}, "copyIcon": true}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "Certificate Authorities \u2014 " + cas.length});
            }
        }
        // Parse templates
        if(hasTemplates){
            let templates = [];
            let inTemplates = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.startsWith("Certificate Templates")) { inTemplates = true; continue; }
                if(trimmed.startsWith("ADCS Vulnerability") || trimmed.startsWith("ESC6")) break;
                if(!inTemplates) continue;
                let tplMatch = trimmed.match(/^\[(\d+)\]\s+(\S+)\s*(?:\((.+)\))?/);
                if(tplMatch){
                    templates.push({num: tplMatch[1], name: tplMatch[2], display: tplMatch[3] || "", subject: "", ekus: "", raSigs: "", schema: ""});
                    continue;
                }
                if(templates.length > 0){
                    let t = templates[templates.length - 1];
                    let subMatch = trimmed.match(/^Subject:\s+(.*)/);
                    if(subMatch) t.subject = subMatch[1];
                    let ekuMatch = trimmed.match(/^EKUs:\s+(.*)/);
                    if(ekuMatch) t.ekus = ekuMatch[1];
                    let raMatch = trimmed.match(/^RA Sigs:\s+(.*)/);
                    if(raMatch) t.raSigs = raMatch[1];
                    let schMatch = trimmed.match(/^Schema:\s+(.*)/);
                    if(schMatch) t.schema = schMatch[1];
                }
            }
            if(templates.length > 0){
                let headers = [
                    {"plaintext": "Template", "type": "string", "width": 200},
                    {"plaintext": "Subject", "type": "string", "width": 180},
                    {"plaintext": "EKUs", "type": "string", "fillWidth": true},
                    {"plaintext": "Schema", "type": "string", "width": 70}
                ];
                let rows = [];
                for(let j = 0; j < templates.length; j++){
                    let t = templates[j];
                    let rowStyle = {};
                    let subStyle = {};
                    if(t.subject.includes("ENROLLEE_SUPPLIES_SUBJECT")){
                        rowStyle = {"backgroundColor": "rgba(255,165,0,0.1)"};
                        subStyle = {"color": "#ff8c00", "fontWeight": "bold"};
                    }
                    if(t.ekus.includes("any purpose")){
                        rowStyle = {"backgroundColor": "rgba(255,0,0,0.06)"};
                    }
                    rows.push({
                        "Template": {"plaintext": t.name, "cellStyle": {"fontWeight": "bold"}, "copyIcon": true},
                        "Subject": {"plaintext": t.subject, "cellStyle": subStyle},
                        "EKUs": {"plaintext": t.ekus},
                        "Schema": {"plaintext": t.schema},
                        "rowStyle": rowStyle
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "Certificate Templates \u2014 " + templates.length});
            }
        }
        // Parse vulnerability findings
        if(hasFindings){
            let findings = [];
            let currentTemplate = "";
            let currentCAs = "";
            let inFindings = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.startsWith("ADCS Vulnerability")){ inFindings = true; continue; }
                if(trimmed.startsWith("ESC6 Check")) break;
                if(!inFindings) continue;
                if(trimmed.match(/^={10,}/) || trimmed.match(/^-{10,}/) || trimmed === "") continue;
                let vulnMatch = trimmed.match(/^\[!\]\s+(.+?)\s+\(CA:\s+(.+)\)/);
                if(vulnMatch){
                    currentTemplate = vulnMatch[1];
                    currentCAs = vulnMatch[2];
                    continue;
                }
                if(currentTemplate && trimmed && !trimmed.startsWith("Found ") && !trimmed.startsWith("CAs:")){
                    findings.push({template: currentTemplate, cas: currentCAs, finding: trimmed});
                }
            }
            if(findings.length > 0){
                let headers = [
                    {"plaintext": "Template", "type": "string", "width": 180},
                    {"plaintext": "Finding", "type": "string", "fillWidth": true},
                    {"plaintext": "CA", "type": "string", "width": 150}
                ];
                let rows = [];
                for(let j = 0; j < findings.length; j++){
                    let f = findings[j];
                    rows.push({
                        "Template": {"plaintext": f.template, "cellStyle": {"fontWeight": "bold", "color": "#d94f00"}},
                        "Finding": {"plaintext": f.finding, "copyIcon": true},
                        "CA": {"plaintext": f.cas},
                        "rowStyle": {"backgroundColor": "rgba(255,0,0,0.06)"}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "Vulnerable Templates \u2014 " + findings.length + " findings"});
            }
        }
        // Parse ESC6
        if(hasESC6){
            let esc6Entries = [];
            let inESC6 = false;
            for(let i = 0; i < lines.length; i++){
                let trimmed = lines[i].trim();
                if(trimmed.startsWith("ESC6 Check")){ inESC6 = true; continue; }
                if(!inESC6) continue;
                let esc6Match = trimmed.match(/^(.+?)\s+\((.+?)\):\s+(.*)/);
                if(esc6Match){
                    esc6Entries.push({ca: esc6Match[1], host: esc6Match[2], status: esc6Match[3]});
                }
            }
            if(esc6Entries.length > 0){
                let headers = [
                    {"plaintext": "CA", "type": "string", "width": 200},
                    {"plaintext": "Host", "type": "string", "width": 200},
                    {"plaintext": "ESC6 Status", "type": "string", "fillWidth": true}
                ];
                let rows = [];
                for(let j = 0; j < esc6Entries.length; j++){
                    let e = esc6Entries[j];
                    let isVuln = e.status.includes("VULNERABLE");
                    rows.push({
                        "CA": {"plaintext": e.ca, "cellStyle": {"fontWeight": "bold"}},
                        "Host": {"plaintext": e.host},
                        "ESC6 Status": {"plaintext": e.status, "cellStyle": isVuln ? {"color": "#d94f00", "fontWeight": "bold"} : {"color": "#4caf50"}},
                        "rowStyle": isVuln ? {"backgroundColor": "rgba(255,0,0,0.08)"} : {}
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": "ESC6 Assessment"});
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
