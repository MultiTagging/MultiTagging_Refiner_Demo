import pandas as pd
from ast import literal_eval
import math
import numpy

import os

def electLabel():
    DASP_ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP')
    dict_DASP_ToolsCapacity = DASP_ToolsCapacity.to_dict('records')
    dict_DASP_ToolsCapacity = {item['Tool']:item for item in dict_DASP_ToolsCapacity}
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']


    VoteData =  pd.DataFrame(columns=['id','DASP','1','2','3','4','5','6','7','8','9','10'])
    Tools = sorted([f.name.split('.')[0] for f in os.scandir('./Results/LabeledData') if f.is_file() and 'csv' in f.name])
    
    for Tool in Tools:
        flag = False
        ToolResult = pd.read_csv('./Results/LabeledData/' + Tool + '.csv',converters={Tool+'_DASP_Rank': literal_eval})
        Tool_DASP_Result = createDASPmetrics(Tool, ToolResult)
        if Tools.index(Tool) == 0:
            VoteData['id'] = Tool_DASP_Result['id']
            VoteData['DASP'] = [list() for x in range(len(VoteData.index))]
            for rank in range(1,11):
                VoteData[str(rank)] = [list() for x in range(len(VoteData.index))]
        else:
            flag = True
        for index, row in Tool_DASP_Result.iterrows():
            ID = Tool_DASP_Result.at[index,'id']
            if VoteData.query("id == @ID").shape[0] > 0:
                DestnationIndex =  VoteData.query("id == @ID").index[0]

                for rank in range(1,11):
                    if dict_DASP_ToolsCapacity[Tool][DASP_Labels[rank-1]] == 1:
                        currentValue = VoteData.at[DestnationIndex,'DASP']
                        VoteData.at[DestnationIndex, 'DASP'] = list(set(currentValue + Tool_DASP_Result.at[index, 'DASP']))
                        currentValue = VoteData.at[DestnationIndex,str(rank)]
                        VoteData.at[DestnationIndex,str(rank)] = list(currentValue + Tool_DASP_Result.at[index, str(rank)])
                    '''else:
                        currentValue = VoteResult.at[DestnationIndex,str(rank)]
                        VoteResult.at[DestnationIndex,str(rank)] = list(currentValue + [-1])'''
        if flag:
            for index, row in Tool_DASP_Result.iterrows():
               ID = Tool_DASP_Result.at[index,'id']
               if VoteData.query("id == @ID").shape[0] == 0:
                   last_index = len(VoteData)
                   VoteData.at[last_index,'id'] = Tool_DASP_Result.at[index,'id']
                   VoteData.at[last_index,'DASP'] = Tool_DASP_Result.at[index,'DASP']
                   for rank in range(1,11):
                       VoteData.at[last_index,str(rank)] = Tool_DASP_Result.at[index,str(rank)]
    
    VoteResult = vote(VoteData,'avg') # Threshold: ['avg', 'majority','at least 2','tool power per vulnerablitiy']
    VoteResult = vote(VoteResult,'majority')
    VoteResult = vote(VoteResult,'AtLeast')

    VoteResult.to_csv('./Results/LabeledData/voteBasedData.csv',index=False)
    print(VoteResult)

def vote(VoteData,method):
    VoteResult = add_voteColumns(VoteData,method)

    for index, row in VoteResult.iterrows():
        for rank in range(1,11):
            labelVots = VoteResult.at[index,str(rank)]
            VoteResult.at[index,str(rank)+'_'+method] = vote_methods(labelVots, method)

    return VoteResult

def vote_methods(labelVots,method):
    label = 0
    match method:
        case 'avg':
            label = 1 if numpy.average(labelVots) >= 50 else 0
        case 'majority':
            label = 1 if labelVots.count(1) > labelVots.count(0) else 0
        case 'AtLeast':
            label = 1 if labelVots.count(1) >= 2 else 0
    return label

def add_voteColumns(VoteData,method):
    for rank in range(1,11):
        index = VoteData.columns.get_loc(str(rank))
        VoteData.insert(index+1, str(rank)+'_'+method,'',True)
    return VoteData
        
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
                    DASPmetrics.at[index, str(i)] = [0]
            else:
                for i in range(1,11):
                    DASPmetrics.at[index, str(i)] = [1] if i in DS.at[index,DASP_Label] else [0]
    DASPmetrics.sort_values('id',inplace=True)
    DASPmetrics.reset_index(inplace=True, drop=True)

    return DASPmetrics

electLabel()