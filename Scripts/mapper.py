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
            if row[tool+'_Labels'] == ['error'] or row[tool+'_Labels'] == 'error':
                continue
            elif len(row[tool+'_Labels']) == 0:
                labeledSC.at[index,tool+'_Labels'] = 'safe'
            else:
                SWC_Codes = []
                SWC_Titles= []
                DASP_Ranks = []
                DASP_Titles = []
                labels = row[tool+'_Labels']
                #print('labels: ',labels, ' with length: ', len(labels))
                for label in labels:
                    if VulnerablityMapDF.query("Detectors == @label").shape[0] > 0:
                        Detector_RowIndex = VulnerablityMapDF.query("Detectors == @label").index[0]
                        SWC_Codes.append(VulnerablityMapDF["SWC"].iloc[Detector_RowIndex])
                        DASP_Ranks.append(VulnerablityMapDF["DASP"].iloc[Detector_RowIndex])
                for code in SWC_Codes:
                    SWC_RowIndex = SWCDF.query("Code == @code").index[0]
                    SWC_Titles.append(SWCDF["Title"].iloc[SWC_RowIndex])
                for rank in DASP_Ranks:
                    if not math.isnan(rank):
                        #print('Rank is: ', rank)
                        DASP_RowIndex = DASPDF.query("Rank == @rank").index[0]
                        DASP_Titles.append(DASPDF["Vulnerability"].iloc[DASP_RowIndex])
                
                labeledSC.at[index,tool+'_SWC_Code'] = SWC_Codes
                labeledSC.at[index,tool+'_SWC_Title'] = SWC_Titles
                labeledSC.at[index,tool+'_DASP_Rank'] = DASP_Ranks
                labeledSC.at[index,tool+'_DASP_Title'] = DASP_Titles
        return labeledSC
    except IOError:
        print("Path not exist") 

