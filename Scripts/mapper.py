import pandas as pd
import math

def map(labeledSC,VulnerablityMapFilePath,tool):
    labeledSC[tool+'_SWC_Code'] = ''
    labeledSC[tool+'_SWC_Title'] = ''
    labeledSC[tool+'_DASP_Rank'] = ''
    labeledSC[tool+'_DASP_Title'] = ''
    try:
        VulnerablityMapDF = pd.read_excel(VulnerablityMapFilePath,sheet_name=tool)
        SWCDF = pd.read_excel(VulnerablityMapFilePath,sheet_name='SWC')
        DASPDF = pd.read_excel(VulnerablityMapFilePath,sheet_name='DASP')

        if 'Detectors' not in VulnerablityMapDF.columns:
            for alt in ['Detector', 'detectors', 'Rule', 'ID']:
                if alt in VulnerablityMapDF.columns:
                    VulnerablityMapDF = VulnerablityMapDF.rename(columns={alt: 'Detectors'})
                    break

        for index, row in labeledSC.iterrows():
            SWC_Codes = []
            SWC_Titles= []
            DASP_Ranks = []
            DASP_Titles = []

            labels_val = row.get(tool+'_Labels', {})
            if isinstance(labels_val, dict) and len(labels_val) == 1 and 'error' in labels_val:
                SWC_Codes.append('error')
                SWC_Titles.append('error')
                DASP_Ranks.append('error')
                DASP_Titles.append('error')
                labeledSC.at[index, tool+'_SWC_Code']   = SWC_Codes
                labeledSC.at[index, tool+'_SWC_Title']  = SWC_Titles
                labeledSC.at[index, tool+'_DASP_Rank']  = DASP_Ranks
                labeledSC.at[index, tool+'_DASP_Title'] = DASP_Titles
                continue

            if (isinstance(labels_val, list) and (len(labels_val) == 0 or labels_val == [''])) or \
               (isinstance(labels_val, dict) and len(labels_val) == 0):
                labeledSC.at[index, tool+'_Labels'] = 'safe'
                labeledSC.at[index, tool+'_SWC_Code']   = []
                labeledSC.at[index, tool+'_SWC_Title']  = []
                labeledSC.at[index, tool+'_DASP_Rank']  = []
                labeledSC.at[index, tool+'_DASP_Title'] = []
                continue

            if isinstance(labels_val, dict):
                detectors_iter = list(labels_val.keys())
            else:
                detectors_iter = list(labels_val)

            new_labels_dict = labels_val.copy() if isinstance(labels_val, dict) else {}

            for det in detectors_iter:
                det_key_for_lookup = det

                if tool == 'Mythril':
                    if isinstance(det_key_for_lookup, str) and det_key_for_lookup.startswith('SWC'):
                        parts = det_key_for_lookup.split('-')
                        if len(parts) > 1:
                            det_key_for_lookup = parts[1]
                    try:
                        det_key_for_lookup = int(det_key_for_lookup)
                    except Exception:
                        pass

                try:
                    det_rows = VulnerablityMapDF.query("Detectors == @det_key_for_lookup")
                except Exception:
                    det_rows = pd.DataFrame()

                swc_code = None
                dasp_rank = None
                if not det_rows.empty:
                    swc_code = det_rows["SWC"].iloc[0] if "SWC" in det_rows.columns else None
                    dasp_rank = det_rows["DASP"].iloc[0] if "DASP" in det_rows.columns else None

                push_uniqueInt(SWC_Codes, swc_code)
                push_uniqueInt(DASP_Ranks, dasp_rank)

                if isinstance(new_labels_dict, dict):
                    meta = new_labels_dict.get(det, None)
                    if not isinstance(meta, dict):
                        meta = {"lines": [], "SWC": [], "DASP": []}
                    if isinstance(meta.get("SWC", []), list) and len(meta.get("SWC", [])) == 0:
                        if convert_int_or_none(swc_code) is not None:
                            meta["SWC"] = [convert_int_or_none(swc_code)]
                    if isinstance(meta.get("DASP", []), list) and len(meta.get("DASP", [])) == 0:
                        if convert_int_or_none(dasp_rank) is not None:
                            meta["DASP"] = [convert_int_or_none(dasp_rank)]
                    new_labels_dict[det] = meta
            
            for code in SWC_Codes:
                try:
                    if not math.isnan(code):  
                        SWC_RowIndex = SWCDF.query("Code == @code").index[0]
                        SWC_Titles.append(SWCDF["Title"].iloc[SWC_RowIndex])
                except Exception:
                    pass
            for rank in DASP_Ranks:
                try:
                    if not math.isnan(rank):
                        DASP_RowIndex = DASPDF.query("Rank == @rank").index[0]
                        DASP_Titles.append(DASPDF["Vulnerability"].iloc[DASP_RowIndex])
                except Exception:
                    pass

            labeledSC.at[index,tool+'_SWC_Code'] = list(dict.fromkeys([x for x in SWC_Codes   if str(x) != 'nan']))
            labeledSC.at[index,tool+'_SWC_Title'] = list(dict.fromkeys(SWC_Titles))
            labeledSC.at[index,tool+'_DASP_Rank'] = list(dict.fromkeys([x for x in DASP_Ranks  if str(x) != 'nan']))
            labeledSC.at[index,tool+'_DASP_Title'] = list(dict.fromkeys(DASP_Titles))

            if isinstance(new_labels_dict, dict):
                labeledSC.at[index, tool+'_Labels'] = new_labels_dict

        return labeledSC
    except IOError:
        print("Path not exist")
#-------------------------------------------
# Helpers
#-------------------------------------------
def convert_int_or_none(x):
    try:
        value = int(float(x))
        return value
    except Exception:
        return None

def push_uniqueInt(lst, val):
    value = convert_int_or_none(val)
    if value is not None and value not in lst:
        lst.append(value)