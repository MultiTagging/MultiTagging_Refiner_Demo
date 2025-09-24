import pandas as pd
import os
import json, re
from pathlib import Path
import numpy as np
#-------------------------------------------
#Get the correct path to the reports main directory
#-------------------------------------------
self_dir = Path(__file__).resolve().parents[1]
#-------------------------------------------
def parse(tool,reportsLocation,reportSource):
    path = self_dir /reportsLocation
    toolTags = pd.DataFrame(columns=['contractAddress', tool+'_Labels'])
    match reportSource:
        case 0:
            match tool:
                case 'Mythril':
                    try:
                        for filename in os.listdir(path):
                            codes = {}
                            fpath = path/filename
                            if filename.endswith('.txt'):
                                if os.path.getsize(fpath) != 0:
                                    with open(fpath, errors="ignore") as file:
                                        for line in file:
                                            if 'SWC ID' in line:
                                                label = line.rstrip()
                                                entry = codes.setdefault(label, {"lines": [], "SWC": [], "DASP": []})
                                                ensure(entry)
                                else:
                                    codes = {'error': {"lines": [], "SWC": [], "DASP": []}}
                            elif filename.endswith('.json'):
                                if os.path.getsize(fpath) != 0:
                                    with open(fpath, errors="ignore") as file:
                                        data = json.load(file)
                                    issues = data.get('issues', [])
                                    if not isinstance(issues, list): issues = []
                                    if len(issues) == 0 and 'success' in data:
                                        if not data['success']:
                                            codes = {'error': {"lines": [], "SWC": [], "DASP": []}}
                                        else:
                                            codes = {}
                                    else:
                                        for issue in issues:
                                            label = issue.get('swc-id') or issue.get('swcID') or issue.get('title', 'mythril-issue')
                                            entry = codes.setdefault(label, {"lines": [], "SWC": [], "DASP": []}); ensure(entry)

                                            if issue.get('swc-id') or issue.get('swcID'):
                                                entry["SWC"].append(issue.get('swc-id') or issue.get('swcID'))

                                            append_str(entry["files"], issue.get('filename') or issue.get('filePath'))
                                            append_str(entry["contracts"], issue.get('contract'))
                                            append_str(entry["functions"], issue.get('function'))
                                            append_str(entry["severities"], issue.get('severity'))
                                            append_str(entry["messages"], issue.get('description') or issue.get('message') or issue.get('title'))

                                            if 'lineno' in issue:
                                                append_int(entry["lines"], issue.get('lineno'))

                                            locations = issue.get('locations') or issue.get('external_locations') or []
                                            for loc in locations:
                                                if isinstance(loc, dict):
                                                    for k in ('line','lineno','start_line','row'):
                                                        if k in loc: append_int(entry["lines"], loc.get(k))
                                                    if 'end_line' in loc: append_int(entry["end_lines"], loc.get('end_line'))

                                                    sm = loc.get('source_map') or loc.get('sourceMap')
                                                    if isinstance(sm, dict):
                                                        if 'line' in sm:
                                                            append_int(entry["lines"], sm.get('line'))
                                                        elif isinstance(sm.get('lines'), list):
                                                            for value in sm.get('lines') or []:
                                                                append_int(entry["lines"], value)

                                            dedupe(entry)
                                else:
                                    codes = {'error': {"lines": [], "SWC": [], "DASP": []}}

                            toolTags.loc[len(toolTags)] = [filename.rstrip().rsplit('.')[0], codes]

                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
                case 'Solhint':
                    try:
                        for filename in os.listdir(path):
                            if filename.endswith('.json'):
                                fpath = path/filename
                                codes = {}

                                if os.path.getsize(fpath) != 0:
                                    with open(fpath, errors="ignore") as file:
                                        data = json.load(file)

                                    if isinstance(data, dict) and ('ruleId' not in data.keys()) and (str(data.get('severity', '')).lower() == 'error'):
                                        codes = {'error': {"lines": [], "SWC": [], "DASP": []}}
                                    elif isinstance(data, list) and 'ruleId' not in data[0].keys() and data[0]['severity'][0] == 'Error':
                                        codes = {'error': {"lines": [], "SWC": [], "DASP": []}}
                                    else:
                                        records = data if isinstance(data, list) else [data]
                                        for msg in records:
                                            if not isinstance(msg, dict):
                                                continue
                                            label = msg.get('ruleId') or 'Solhint-rule'
                                            entry = codes.setdefault(label, {"lines": [], "SWC": [], "DASP": []}); ensure(entry)

                                            append_int(entry["lines"], msg.get('line'))
                                            append_int(entry["end_lines"], msg.get('endLine') or msg.get('line'))
                                            append_int(entry["columns"], msg.get('column'))
                                            append_str(entry["files"], msg.get('filePath') or msg.get('filename'))
                                            append_str(entry["severities"], msg.get('severity'))
                                            append_str(entry["messages"], msg.get('message'))

                                        for entry in codes.values(): dedupe(entry)
                                else:
                                    codes = {'error': {"lines": [], "SWC": [], "DASP": []}}

                                toolTags.loc[len(toolTags)] = [filename.rstrip().rsplit('.')[0], codes]

                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
                case 'Slither':
                    try:
                        for filename in os.listdir(path):
                            if filename.endswith('.json'):
                                fpath = path/filename
                                codes = {}

                                if os.path.getsize(fpath) != 0:
                                    with open(fpath, errors="ignore") as file:
                                        data = json.load(file)

                                    if 'success' in data and data['success'] is not True:
                                        codes = {'error': {"lines": [], "SWC": [], "DASP": []}}
                                    else:
                                        detectors = (data.get('results', {}) or {}).get('detectors', []) \
                                                    or data.get('detectors', []) or []

                                        for detector in detectors:
                                            if not isinstance(detector, dict):
                                                continue
                                            label = detector.get('check') or detector.get('id') or 'slither-issue'
                                            entry = codes.setdefault(label, {"lines": [], "SWC": [], "DASP": []}); ensure(entry)

                                            file_path = None
                                            func_name = None
                                            func_sig = None
                                            contract_name = None

                                            for element in detector.get('elements', []) or []:
                                                sm = (element or {}).get('source_mapping', {}) or {}
                                                if isinstance(sm.get('lines'), list):
                                                    for value in sm.get('lines'): append_int(entry["lines"], value)
                                                elif 'line' in sm:
                                                    append_int(entry["lines"], sm.get('line'))
                                                if not file_path:
                                                    file_path = sm.get('filename_relative') or sm.get('filename_absolute') or sm.get('filename_short')

                                                if element.get('type') == 'function':
                                                    func_name = func_name or element.get('name')
                                                    func_sig  = func_sig or (element.get('type_specific_fields', {}) or {}).get('signature')
                                                    parent = (element.get('type_specific_fields', {}) or {}).get('parent', {})
                                                    if isinstance(parent, dict) and parent.get('type') == 'contract':
                                                        contract_name = contract_name or parent.get('name')
                                                elif element.get('type') == 'node' and not func_name:
                                                    tsf = (element.get('type_specific_fields', {}) or {})
                                                    parent_fn = tsf.get('parent', {})
                                                    if isinstance(parent_fn, dict):
                                                        func_name = func_name or parent_fn.get('name')
                                                        func_sig  = func_sig or (parent_fn.get('type_specific_fields', {}) or {}).get('signature')
                                                        grand = (parent_fn.get('type_specific_fields', {}) or {}).get('parent', {})
                                                        if isinstance(grand, dict) and grand.get('type') == 'contract':
                                                            contract_name = contract_name or grand.get('name')

                                            fme = str(detector.get('first_markdown_element','')).strip()
                                            m = re.search(r'#L(\d+)-L(\d+)$', fme)
                                            if m:
                                                append_int(entry["lines"], int(m.group(1)))
                                                append_int(entry["end_lines"], int(m.group(2)))

                                            append_str(entry["files"], file_path)
                                            append_str(entry["contracts"], contract_name)
                                            append_str(entry["functions"], func_sig or func_name)
                                            append_str(entry["severities"], detector.get('impact'))
                                            append_str(entry["messages"], detector.get('description'))

                                        for entry in codes.values(): dedupe(entry)
                                else:
                                    codes = {'error': {"lines": [], "SWC": [], "DASP": []}}

                                toolTags.loc[len(toolTags)] = [filename.rstrip().rsplit('.')[0], codes]

                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
                case 'VeriSmart':
                    try:
                        toolTags[tool + '_AnalysisTime'] = ''
                        for filename in os.listdir(path):
                            codes = {}
                            analysis_time = ''
                            fpath = path/filename

                            if os.path.getsize(fpath) != 0:
                                with open(fpath, errors="ignore") as file:
                                    data = json.load(file)

                                if data.get('errMsg') == None:
                                    for finding in data.get('result', []):
                                        if not isinstance(finding, dict):
                                            continue
                                        if finding.get('status') == 'unproven':
                                            label = finding.get('kind')
                                            entry = codes.setdefault(label, {"lines": [], "SWC": [], "DASP": []}); ensure(entry)

                                            for key in ('line','lineno','start_line','row'):
                                                if key in finding:
                                                    append_int(entry["lines"], finding.get(key))
                                                    append_int(entry["end_lines"], finding.get(key))
                                                    break
                                            append_str(entry["files"], finding.get('file') or finding.get('filename'))
                                            append_str(entry["messages"], finding.get('desc') or finding.get('message') or finding.get('note'))
                                            append_str(entry["severities"], finding.get('severity') or finding.get('impact'))

                                    for entry in codes.values(): dedupe(entry)
                                else:
                                    codes = {'error': {"lines": [], "SWC": [], "DASP": []}}

                                analysis_time = data.get('time', '')
                            else:
                                codes = {'error': {"lines": [], "SWC": [], "DASP": []}}
                                analysis_time = ''

                            toolTags.loc[len(toolTags)] = {'contractAddress': filename.rstrip().rsplit('.')[0],
                                                           tool + '_Labels': codes,
                                                           tool + '_AnalysisTime': analysis_time}

                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
        case 1:
            try:
                reportsDF = pd.DataFrame()
                for filename in os.listdir(path):
                    if filename.endswith('.csv'):
                        df = pd.read_csv(path/filename)
                        reportsDF = pd.concat([reportsDF, df], ignore_index=True)

                reportsDF.columns = [str(c).strip().lower().replace(" ", "_") for c in reportsDF.columns]

                if "file" in reportsDF.columns and any(c in reportsDF.columns for c in ["rule_id","check_id","rule","id"]):
                    label_col = "rule_id" if "rule_id" in reportsDF.columns else ("check_id" if "check_id" in reportsDF.columns else ("rule" if "rule" in reportsDF.columns else "id"))
                    codes_all = {}
                    for _, r in reportsDF.iterrows():
                        base = os.path.basename(str(r.get("file","")))
                        contractAddress = base.replace(".sol","") if base else "unknown"
                        codes = codes_all.setdefault(contractAddress, {})
                        label = str(r.get(label_col,"")).strip() or "rule"
                        entry = codes.setdefault(label, {"lines": [], "SWC": [], "DASP": []}); ensure(entry)

                        append_str(entry["files"], r.get("file"))
                        append_int(entry["lines"], r.get("line") or r.get("start_line"))
                        append_int(entry["end_lines"], r.get("end_line") or r.get("line") or r.get("start_line"))
                        append_str(entry["severities"], r.get("severity") or r.get("level") or r.get("impact"))
                        append_str(entry["messages"], r.get("message") or r.get("msg") or r.get("description"))

                    for codes in codes_all.values():
                        for entry in codes.values():
                            dedupe(entry)

                    out_rows = [{"contractAddress": k, tool + "_Labels": value} for k,value in codes_all.items()]
                    out_df = pd.DataFrame(out_rows)
                    print(tool + " tags have been extracted successfully")
                    return out_df

                reportsDF = reportsDF.drop_duplicates(subset='basename', keep='last') if 'basename' in reportsDF.columns else reportsDF
                if 'basename' in reportsDF.columns:
                    reportsDF['contractAddress'] = reportsDF['basename'].str.replace('.sol', '', regex=False)

                if 'errors' in reportsDF.columns and 'findings' in reportsDF.columns:
                    reportsDF['findings'] = np.where((reportsDF['findings'] == '{}') & (reportsDF['errors'] != '{}'),
                                            'error',reportsDF['findings'])

                def parse_findings_cell(cell):
                    if isinstance(cell, str):
                        s = cell.strip()
                        if s == 'error': return {'error': {"lines": [], "SWC": [], "DASP": []}}
                        if s in ('{}','{ }'): return {}
                        if s.startswith('{') and s.endswith('}'):
                            inner = s[1:-1].strip()
                            if not inner: return {}
                            labels = [x.strip() for x in inner.split(',') if x.strip()]
                            return { lab: {"lines": [], "SWC": [], "DASP": []} for lab in labels }
                        return { s: {"lines": [], "SWC": [], "DASP": []} } if s else {}
                    return {}

                labels_col = reportsDF['findings'].apply(parse_findings_cell) if 'findings' in reportsDF.columns else pd.Series([{}]*len(reportsDF))

                out_df = pd.DataFrame({'contractAddress': reportsDF['contractAddress'] if 'contractAddress' in reportsDF.columns else pd.Series(["unknown"]*len(reportsDF)),
                    tool + '_Labels': labels_col,tool + '_AnalysisTime': reportsDF['duration'] if 'duration' in reportsDF.columns else None})
                print(tool + " tags have been extracted successfully")
                return out_df
            except IOError:
                print("Path not exist")
#-------------------------------------------
# Helpers
#-------------------------------------------
def append_int(dst, value):
    try:
        iv = int(value)
        if iv > 0:
            dst.append(iv)
    except Exception:
        pass
def append_str(dst, value):
    if value is None: return
    s = str(value).strip()
    if s: dst.append(s)
def ensure(entry):
    for k in ["files","contracts","functions","end_lines","columns","severities","messages"]:
        if k not in entry: entry[k] = []
def dedupe(entry):
    try: entry["lines"] = sorted({int(x) for x in entry.get("lines", [])})
    except Exception: pass
    try: entry["end_lines"] = sorted({int(x) for x in entry.get("end_lines", [])})
    except Exception: pass
    try: entry["columns"] = sorted({int(x) for x in entry.get("columns", [])})
    except Exception: pass
    for k in ["files","contracts","functions","severities","messages"]:
        values = [str(x) for x in entry.get(k, []) if x not in (None,"")]

        seen, out = set(), []
        for value in values:
            if value not in seen:
                seen.add(value)
                out.append(value)
        entry[k] = out