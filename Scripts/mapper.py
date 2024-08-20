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

        for index, row in labeledSC.iterrows():
            SWC_Codes = []
            SWC_Titles= []
            DASP_Ranks = []
            DASP_Titles = []
            if (len(row[tool+'_Labels']) == 1 and 'error' in row[tool+'_Labels']) or row[tool+'_Labels'] == 'error':
                SWC_Codes.append('error')
                SWC_Titles.append('error')
                DASP_Ranks.append('error')
                DASP_Titles.append('error')
            elif tool.lower() == 'solhint' and (len(row[tool+'_Labels']) == 0 or row[tool+'_Labels'].all() == ['']): #solhint: elif len(row[tool+'_Labels']) == 0 or row[tool+'_Labels'].all() == ['']:
                labeledSC.at[index,tool+'_Labels'] = 'safe'
            elif tool.lower() != 'solhint' and (len(row[tool+'_Labels']) == 0 or row[tool+'_Labels'] == ['']): #solhint: elif len(row[tool+'_Labels']) == 0 or row[tool+'_Labels'].all() == ['']:
                labeledSC.at[index,tool+'_Labels'] = 'safe'  
            else:
                labels = row[tool+'_Labels']
                for label in labels:
                    if tool == 'Mythril':
                        if label.startswith('SWC'): label = label.split('-')[1]
                        label = int(label)
                    if VulnerablityMapDF.query("Detectors == @label").shape[0] > 0:
                        Detector_RowIndex = VulnerablityMapDF.query("Detectors == @label").index[0]
                        SWC_Codes.append(VulnerablityMapDF["SWC"].iloc[Detector_RowIndex])
                        DASP_Ranks.append(VulnerablityMapDF["DASP"].iloc[Detector_RowIndex])
                for code in SWC_Codes:
                    if not math.isnan(code):
                        SWC_RowIndex = SWCDF.query("Code == @code").index[0]
                        SWC_Titles.append(SWCDF["Title"].iloc[SWC_RowIndex])
                for rank in DASP_Ranks:
                    if not math.isnan(rank):
                        DASP_RowIndex = DASPDF.query("Rank == @rank").index[0]
                        DASP_Titles.append(DASPDF["Vulnerability"].iloc[DASP_RowIndex])
                
                SWC_Codes = list(filter(lambda x: str(x) != 'nan', SWC_Codes))
                DASP_Ranks = list(filter(lambda x: str(x) != 'nan', DASP_Ranks))
                
            labeledSC.at[index,tool+'_SWC_Code'] = list(dict.fromkeys(SWC_Codes))
            labeledSC.at[index,tool+'_SWC_Title'] = list(dict.fromkeys(SWC_Titles))
            labeledSC.at[index,tool+'_DASP_Rank'] = list(dict.fromkeys(DASP_Ranks))
            labeledSC.at[index,tool+'_DASP_Title'] = list(dict.fromkeys(DASP_Titles))
        return labeledSC
    except IOError:
        print("Path not exist") 