import pandas as pd
from ast import literal_eval

import os

def electLabel():
    DASP_ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP')
    dict_DASP_ToolsCapacity = DASP_ToolsCapacity.to_dict('records')

    VoteResult =  pd.DataFrame(columns=['id','DASP','1','2','3','4','5','6','7','8','9','10'])
    Tools = [f.name.split('.')[0] for f in os.scandir('./Results/LabeledData') if f.is_file() and 'csv' in f.name]

    for Tool in Tools:
        ToolResult = pd.read_csv('./Results/LabeledData/' + Tool + '.csv',converters={Tool+'_DASP_Rank': literal_eval})
        Tool_DASP_Result = createDASPmetrics(Tool, ToolResult)
        if Tools.index(Tool) == 0:
            VoteResult = Tool_DASP_Result
        else:
            #loop in ID >> use ToolResult DS
            # find index in VoteResult
                #add ID if not found in VoteResult
                #sum labels
        
        print(VoteResult)

def createDASPmetrics(tool,DS):
    DASPmetrics =  pd.DataFrame(columns=['id','DASP','1','2','3','4','5','6','7','8','9','10'])
    address = 'contractAddress'
    DASP_Label = tool+'_DASP_Rank'

    for index, row in DS.iterrows():
        if len(DS.at[index,DASP_Label]) == 1 and 'error' in DS.at[index,DASP_Label]:
            continue
        else:
            DASPmetrics.at[index,'id'] = DS[address].iloc[index]
            DASPmetrics.at[index,'DASP'] = DS[DASP_Label].iloc[index]
            if DS.at[index,DASP_Label] == 'safe':
                for i in range(1,11):
                    DASPmetrics.at[index, str(i)] = 0
            else:
                for i in range(1,11):
                    DASPmetrics.at[index, str(i)] = 1 if i in DS.at[index,DASP_Label] else 0
    DASPmetrics.sort_values('id',inplace=True)
    DASPmetrics.reset_index(inplace=True, drop=True)

    return DASPmetrics

electLabel()