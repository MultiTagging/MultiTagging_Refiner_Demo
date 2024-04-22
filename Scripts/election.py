import pandas as pd
from ast import literal_eval
import numpy
import os

def electLabel(Voters):
    try:
        DASP_ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP')
        dict_DASP_ToolsCapacity = DASP_ToolsCapacity.to_dict('records')
        dict_DASP_ToolsCapacity = {item['Tool']:item for item in dict_DASP_ToolsCapacity}
        DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']

        VoteData =  pd.DataFrame(columns=['id','Tools','DASP','1','2','3','4','5','6','7','8','9','10'])
        if len(Voters) == 1 and Voters[0].lower() == 'all':
            Tools = sorted([f.name.split('.')[0] for f in os.scandir('./Results/LabeledData') if f.is_file() and 'csv' in f.name and f.name != 'voteBasedData.csv'])
        else:
            Tools = Voters
        
        for Tool in Tools:
            ToolResult = pd.read_csv('./Results/LabeledData/' + Tool + '.csv',converters={Tool+'_DASP_Rank': literal_eval})
            Tool_DASP_Result = createDASPmetrics(Tool, ToolResult,dict_DASP_ToolsCapacity)
            #To fill the VoteData DF for the first time using the first tool.  This block create a DF with ids from the first tool.
            if Tools.index(Tool) == 0:
                VoteData['id'] = Tool_DASP_Result['id']
                VoteData['DASP'] = [list() for x in range(len(VoteData.index))]
                VoteData['Tools']= [list() for x in range(len(VoteData.index))]
                for rank in range(1,11):
                    VoteData[str(rank)] = [list() for x in range(len(VoteData.index))]
            
            #To update the VoteData DF using other tools vote
            unfoundIDs = []
            for index, row in Tool_DASP_Result.iterrows():
                ID = Tool_DASP_Result.at[index,'id']
                if VoteData.query("id == @ID").shape[0] > 0:
                    DestnationIndex =  VoteData.query("id == @ID").index[0]
                    currentValue = VoteData.at[DestnationIndex,'Tools']
                    VoteData.at[DestnationIndex, 'Tools'] = list(set(currentValue + [Tool]))

                    for rank in range(1,11):
                        if dict_DASP_ToolsCapacity[Tool][DASP_Labels[rank-1]] == 1:
                            currentValue = VoteData.at[DestnationIndex,'DASP']
                            VoteData.at[DestnationIndex, 'DASP'] = list(set(currentValue + Tool_DASP_Result.at[index, 'DASP']))
                            currentValue = VoteData.at[DestnationIndex,str(rank)]
                            #print(currentValue,'_And_',Tool_DASP_Result.at[index, str(rank)])
                            VoteData.at[DestnationIndex,str(rank)] = list(currentValue + Tool_DASP_Result.at[index, str(rank)])
                else:
                    unfoundIDs.append(ID)
            #To add new ids for samples that were not analyzed by the previous tools.
            if len(unfoundIDs)>0:
                for ID in unfoundIDs:
                    unfounIDIndex =  Tool_DASP_Result.query("id == @ID").index[0]
                    last_index = len(VoteData)
                    VoteData.at[last_index,'id'] = Tool_DASP_Result.at[unfounIDIndex,'id']
                    VoteData.at[last_index,'Tools'] = [Tool]
                    VoteData.at[last_index,'DASP'] = Tool_DASP_Result.at[unfounIDIndex,'DASP']
                    for rank in range(1,11):
                        VoteData.at[last_index,str(rank)] = Tool_DASP_Result.at[unfounIDIndex,str(rank)]
        
        VoteResult = vote(VoteData,'Threshold') # Threshold: ['Threshold', 'Majority','AtLeast 1','tool power per vulnerablitiy']
        VoteResult = vote(VoteResult,'Majority')
        VoteResult = vote(VoteResult,'AtLeastOne')

        VoteResult.to_csv('./Results/LabeledData/voteBasedData.csv',index=False)
        #print(VoteResult)
        return VoteResult
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
def vote(VoteData,method):
    VoteResult = add_voteColumns(VoteData,method)

    for index, row in VoteResult.iterrows():
        for rank in range(1,11):
            labelVots = VoteResult.at[index,str(rank)]
            if len(labelVots) > 0:
                VoteResult.at[index,str(rank)+'_'+method] = vote_methods(labelVots, method)
            else:
                VoteResult.at[index,str(rank)+'_'+method] = None
    return VoteResult

def vote_methods(labelVots,method):
    label = 0
    match method:
        case 'Threshold': ## change to threshold value
            label = 1 if numpy.average(labelVots) >= 0.50 else 0
        case 'Majority':
            label = 1 if labelVots.count(1) > labelVots.count(0) else 0
        case 'AtLeastOne':
            label = 1 if labelVots.count(1) >= 1 else 0
    return label

def add_voteColumns(VoteData,method):
    for rank in range(1,11):
        index = VoteData.columns.get_loc(str(rank))
        VoteData.insert(index+1, str(rank)+'_'+method,'',True)
    return VoteData
        
def createDASPmetrics(tool,DS,dict_DASP_ToolsCapacity):
    DASPmetrics =  pd.DataFrame(columns=['id','DASP','1','2','3','4','5','6','7','8','9','10'])
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']

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
                    if dict_DASP_ToolsCapacity[tool][DASP_Labels[i-1]] == 1:
                        DASPmetrics.at[index, str(i)] = [0]
                    else:
                        DASPmetrics.at[index, str(i)] =[]
            else:
                for i in range(1,11):
                    if dict_DASP_ToolsCapacity[tool][DASP_Labels[i-1]] == 1:
                        DASPmetrics.at[index, str(i)] = [1] if i in DS.at[index,DASP_Label] else [0]
                    else:
                        DASPmetrics.at[index, str(i)] =[]

    DASPmetrics.sort_values('id',inplace=True)
    DASPmetrics.reset_index(inplace=True, drop=True)

    return DASPmetrics

#electLabel(['All'])