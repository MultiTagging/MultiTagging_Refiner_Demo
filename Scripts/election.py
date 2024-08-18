import pandas as pd
from ast import literal_eval
import numpy as np
import os
import math
from Scripts.commonSamples import get_commonSamples

def electLabel(Base, Voters,Fair):
    try:
        DASP_ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP')
        dict_DASP_ToolsCapacity = DASP_ToolsCapacity.to_dict('records')
        dict_DASP_ToolsCapacity = {item['Tool']:item for item in dict_DASP_ToolsCapacity}
        DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']

        VoteData =  pd.DataFrame(columns=['id','Tools','DASP','1','2','3','4','5','6','7','8','9','10'])
        if len(Voters) == 1 and Voters[0].lower() == 'all':
            Tools = sorted([f.name.split('.')[0] for f in os.scandir('./Results/LabeledData') if f.is_file() and 'csv' in f.name and not f.name in ['voteBasedData.csv','AllToolsData.csv','voteBasedData_Fair.csv','AllToolsData_Fair.csv']])
        else:
            Tools = Voters
        commonAdrr = pd.DataFrame()
        if Fair:
            #Git common addr
            commonAdrr = pd.DataFrame()
            commonAdrr['contractAddress'] =  get_commonSamples(Tools)

        for Tool in Tools:
            ToolResult = pd.read_csv('./Results/LabeledData/' + Tool + '.csv',converters={Tool+'_DASP_Rank': literal_eval})

            if Fair:
                #remove uncommon addr
                ToolResult.drop(ToolResult[~ToolResult['contractAddress'].isin(commonAdrr['contractAddress'])].index, inplace=True) 
                ToolResult.reset_index(inplace=True, drop=True)

            Tool_DASP_Result = createDASPmetrics(Tool, ToolResult,dict_DASP_ToolsCapacity)

            #To fill the VoteData DF for the first time using the first tool. This block create a DF with ids from the first tool.
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
            #To add new ids for samples that were not analyzed by the previous tools for unfair vote.
            if len(unfoundIDs)>0 and not Fair:
                for ID in unfoundIDs:
                    unfounIDIndex =  Tool_DASP_Result.query("id == @ID").index[0]
                    last_index = len(VoteData)
                    VoteData.at[last_index,'id'] = Tool_DASP_Result.at[unfounIDIndex,'id']
                    VoteData.at[last_index,'Tools'] = [Tool]
                    VoteData.at[last_index,'DASP'] = Tool_DASP_Result.at[unfounIDIndex,'DASP']
                    for rank in range(1,11):
                        VoteData.at[last_index,str(rank)] = Tool_DASP_Result.at[unfounIDIndex,str(rank)]
        #---------------------
        # Apply voting methods
        #---------------------
        VoteResult = Power_based_vote(VoteData,Base, Tools,dict_DASP_ToolsCapacity,DASP_Labels,Fair,commonAdrr)
        print('Power_based_vote is done')
        VoteResult = vote(VoteResult,'Majority')
        VoteResult = vote(VoteResult,'AtLeastOne')
        
        if Fair:
            VoteResult.to_csv('./Results/LabeledData/voteBasedData_Fair.csv',index=False)
        else:
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
                VoteResult.at[index,str(rank)+'_'+method] = 0 #not vulnerable

    return VoteResult

def vote_methods(labelVots,method):
    label = 0
    match method:
        case 'Majority':
            label = 1 if labelVots.count(1) >= labelVots.count(0) else 0
        case 'AtLeastOne':
            label = 1 if labelVots.count(1) >= 1 else 0
    return label

def Power_based_vote(VoteData,Base, Tools,dict_DASP_ToolsCapacity,DASP_Labels,Fair,commonAdrr):
    
    #[1]Identify tool sensitivity rate [High | Low]
    #----------------------------------------------
    toolsPerformanceDic = get_toolsPerformance(Base, Tools,DASP_Labels,Fair)
    print('toolsPerformanceDic:\n',toolsPerformanceDic)

    #[2]Identify tool role [Voter | Inverter | None]
    #------------------------------------------------------
    toolsOVerlapDegree = get_toolsOVerlapDegree(DASP_Labels,Tools,Fair)
    print('toolsOVerlapDegree:\n',toolsOVerlapDegree)
    toolsRules = get_toolRole(toolsPerformanceDic,toolsOVerlapDegree)
    print('toolsRule:\n',toolsRules)

    #[3]Identify voting method for each vulnerability
    #------------------------------------------------
    votingMethod = get_votingMethod(toolsPerformanceDic,toolsRules)
    print('votingMethod:\n',votingMethod)
    #[4]Invert positive flags for overlapping samples of other tools
    #---------------------------------------------------------------
    #[5]Apply vote
    #-------------
    VoteResult = add_voteColumns(VoteData,'Power-based')
    Tool_DASP_Result = get_Tools_DASP_Result(Tools,dict_DASP_ToolsCapacity,Fair,commonAdrr)
    
    for index, row in VoteResult.iterrows():
        for i in range(1, len(DASP_Labels)+1):
            if i in [9,10]:
                continue
            label = DASP_Labels[i-1]

            votingRules = votingMethod[label]
            
            if len(votingRules['Majority']) == len(votingRules['AtLeastOne']) == 0:
                continue
            
            Majority = []
            AtLeastOne = []

            for tool in votingRules['Voters']:
                if tool in votingRules['Inverter'].keys() and (Tool_DASP_Result.at[index,tool+'_'+str(i)] == Tool_DASP_Result.at[index,votingRules['Inverter'][tool]+'_'+str(i)] == 1):
                    toolLabel = 0
                else:
                    toolLabel = Tool_DASP_Result.at[index,tool+'_'+str(i)]
                
                if tool in votingRules['AtLeastOne']:
                    AtLeastOne.append(toolLabel)
                else:
                    Majority.append(toolLabel)

            if len(Majority) == 0:
                VoteResult.at[index,str(i)+'_Power-based'] = 1 if 1 in AtLeastOne else 0
            elif len(AtLeastOne) == 0:
                VoteResult.at[index,str(i)+'_Power-based'] = 1 if Majority.count(1) >= Majority.count(0) else 0
            else:
                VoteResult.at[index,str(i)+'_Power-based'] = 1 if 1 in AtLeastOne or Majority.count(1) >= Majority.count(0) else 0

    return VoteResult

#Identify voting method for each vulnerability
#------------------------------------------------
def get_votingMethod(toolsPerformanceDic,toolsRules):
    votingMethod = {}

    for label in toolsPerformanceDic.keys():
        votingMethod[label] ={}
        LowPerformTools = []
        HighPerformTools = []
        Voters = []
        Inverter = {}
        for tool in toolsPerformanceDic[label].keys():
            if toolsRules[label][tool] != 'None':
                if toolsRules[label][tool] == 'Voter':
                    Voters.append(tool)
                    if toolsPerformanceDic[label][tool]['Recall'] >= 0.95:
                        HighPerformTools.append(tool)
                    else:
                        LowPerformTools.append(tool)
                else:
                    for peer in toolsRules[label][tool].keys():
                        Inverter[peer] = tool

        AtLeastOne = []
        Majority = []
        if len(HighPerformTools) <= 1:
            for tool in toolsPerformanceDic[label].keys():
                if toolsRules[label][tool] == 'Voter':
                    AtLeastOne.append(tool)
        elif len(LowPerformTools) < len(HighPerformTools):
            for tool in toolsPerformanceDic[label].keys():
                if toolsRules[label][tool] == 'Voter':
                    Majority.append(tool)
        else:
            for tool in toolsPerformanceDic[label].keys():
                if toolsRules[label][tool] == 'Voter':
                    if tool in HighPerformTools:
                        Majority.append(tool)
                    else:
                        AtLeastOne.append(tool)
        
        votingMethod[label]['Voters'] = Voters
        votingMethod[label]['Inverter'] = Inverter
        votingMethod[label]['AtLeastOne'] = AtLeastOne
        votingMethod[label]['Majority'] = Majority
    
    votingMethodDF = pd.DataFrame(votingMethod)
    votingMethodDF.insert(0,'Method',['Voters','Inverter','AtLeastOne','Majority'])
    votingMethodDF.to_csv('./Results/VoteResult/votingMethod.csv',index=False)
    return votingMethod

#Identify tool role [Voter | Inverter | None]
#------------------------------------------------------
def get_toolRole(toolsPerformanceDic,toolsOVerlapDegree):
    toolsRule = {}
    for label in toolsPerformanceDic.keys():
        toolsRule[label]={}
        for tool in toolsPerformanceDic[label].keys():
            if math.isnan(toolsPerformanceDic[label][tool]['Precision']):
                toolsRule[label][tool] = 'None'
            elif toolsPerformanceDic[label][tool]['Recall'] <= toolsPerformanceDic[label][tool]['Precision'] and toolsPerformanceDic[label][tool]['Precision'] < 0.20:
                inverterTools = {}
                Flag = False
                for peer in toolsOVerlapDegree[label][tool].keys():
                    if peer != tool and toolsOVerlapDegree[label][tool][peer] != 0 and toolsPerformanceDic[label][tool]['Recall'] == 0 and toolsPerformanceDic[label][peer]['Recall'] > 0:
                        inverterTools[peer] = tool
                    elif peer != tool and toolsPerformanceDic[label][peer]['Recall']-toolsPerformanceDic[label][tool]['Recall'] >= 0.50:
                        if toolsOVerlapDegree[label][tool][peer] >= 60 and toolsPerformanceDic[label][tool]['Recall'] < 0.10:
                            inverterTools[peer] = tool
                        elif toolsOVerlapDegree[label][tool][peer] == 100:
                            toolsRule[label][tool] = 'None'
                            Flag = False
                    if Flag and toolsPerformanceDic[label][tool]['Recall'] == toolsPerformanceDic[label][tool]['Precision'] == 0:
                        toolsRule[label][tool] = 'None'
                    elif len(inverterTools) > 0:
                        toolsRule[label][tool]= inverterTools
                    elif Flag :
                        toolsRule[label][tool] = 'Voter'
            else:
                toolsRule[label][tool] = 'Voter'
    
    toolsRuleDF = pd.DataFrame(toolsRule)
    toolsRuleDF.insert(0,'Tool',list(toolsPerformanceDic[list(toolsPerformanceDic)[0]].keys()))
    toolsRuleDF.to_csv('./Results/VoteResult/powerVoteRules.csv',index=False)
    return toolsRule

def get_toolsOVerlapDegree(DASP_Labels,Tools,Fair):
    if Fair:
        toolsOVerlapDegreeData = pd.read_csv('./Results/Overlap/OverlapDegree_PerVuln_Fair.csv')
    else:
        toolsOVerlapDegreeData = pd.read_csv('./Results/Overlap/OverlapDegree_PerVuln.csv')
    toolsOVerlapDegree = {}
    for v in DASP_Labels:
        toolsOVerlapDegree[v] = {}
        for tool in Tools:
            toolsOVerlapDegree[v][tool] = {}
            for t in Tools:
                toolsOVerlapDegree[v][tool][t] = 0

    for index, row in toolsOVerlapDegreeData.iterrows():
        v = toolsOVerlapDegreeData.at[index,'vulnerability']
        base = toolsOVerlapDegreeData.at[index,'Baseline']
        for t in Tools:
            toolsOVerlapDegree[v][base][t] = toolsOVerlapDegreeData.at[index,t]

    return toolsOVerlapDegree

def get_toolsPerformance(Bases, Tools,DASP_Labels,Fair):
    if Fair:
        resultsPath = './Results/Evaluations_Fair'
    else:
        resultsPath = './Results/Evaluations'

    if Bases[0].lower() == 'all':
        Bases = sorted([d.name for d in os.scandir(resultsPath) if d.is_dir and not d.name.startswith('.')])

    #create output DF (toolsPerformanceDF)
    Metrics = ['Recall','Precision']
    toolsPerformanceDic = {}

    for v in DASP_Labels:
        toolsPerformanceDic[v] = {}
        for t in Tools:
            toolsPerformanceDic[v][t] = {}
            for metric in Metrics:
                toolsPerformanceDic[v][t][metric] = []

    #get the avg performance for each tool
    for base in Bases:
        for tool in Tools:
            toolPerformance_on_base = pd.read_csv(resultsPath + '/' + base + '/' + tool + '.csv')#,converters={'Recall': literal_eval,'Precision': literal_eval,'F1-score': literal_eval})

            for index, row in toolPerformance_on_base.iterrows():
                v = toolPerformance_on_base.at[index,'Label']

                toolsPerformanceDic[v][tool]['Recall'].append(toolPerformance_on_base.at[index,'Recall'])
                toolsPerformanceDic[v][tool]['Precision'].append(toolPerformance_on_base.at[index,'Precision'])

    if len(Bases) >0:
        for v in toolsPerformanceDic.keys():
            for tool in toolsPerformanceDic[v].keys():
                toolsPerformanceDic[v][tool]['Recall'] = np.average(toolsPerformanceDic[v][tool]['Recall'])
                toolsPerformanceDic[v][tool]['Precision'] = np.average(toolsPerformanceDic[v][tool]['Precision'])               
    return toolsPerformanceDic

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

def get_Tools_DASP_Result(Tools,dict_DASP_ToolsCapacity,Fair,commonAdrr):
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']

    Tools_DASP_Result = pd.DataFrame(columns =['id'])

    #Add new columns in the DF for the tool
    for Tool in Tools:
        for i in range(1,11):
            Tools_DASP_Result[Tool+'_'+str(i)] = ''
    for Tool in Tools:
        ToolResult = pd.read_csv('./Results/LabeledData/' + Tool + '.csv',converters={Tool+'_DASP_Rank': literal_eval})
        if Fair:
            ToolResult.drop(ToolResult[~ToolResult['contractAddress'].isin(commonAdrr['contractAddress'])].index, inplace=True) 
            ToolResult.reset_index(inplace=True, drop=True)
        
        Tool_DASP_Result = createDASPmetrics(Tool, ToolResult,dict_DASP_ToolsCapacity)

        #To fill the VoteData DF for the first time using the first tool
        if Tools.index(Tool) == 0:
            Tools_DASP_Result['id'] = Tool_DASP_Result['id']
            
        unfoundIDs = []
        for index, row in Tool_DASP_Result.iterrows():
            ID = Tool_DASP_Result.at[index,'id']
            if Tools_DASP_Result.query("id == @ID").shape[0] > 0:
                DestnationIndex =  Tools_DASP_Result.query("id == @ID").index[0]
                
                for rank in range(1,11):
                    #print(Tool_DASP_Result.at[index, str(rank)]) ##########
                    
                    if len(Tool_DASP_Result.at[index, str(rank)])>0:
                        #print(Tool_DASP_Result.at[index, str(rank)][0]) #########
                        Tools_DASP_Result.at[DestnationIndex,Tool+'_'+str(rank)] = Tool_DASP_Result.at[index, str(rank)][0]
            else:
                unfoundIDs.append(ID)
        #To add new ids for samples that were not analyzed by the previous tools.
        if len(unfoundIDs)>0:
            for ID in unfoundIDs:
                unfounIDIndex =  Tool_DASP_Result.query("id == @ID").index[0]
                last_index = len(Tools_DASP_Result)
                Tools_DASP_Result.at[last_index,'id'] = Tool_DASP_Result.at[unfounIDIndex,'id']
                for rank in range(1,11):
                    if len(Tool_DASP_Result.at[index, str(rank)])>0:
                        Tools_DASP_Result.at[last_index,Tool+'_'+str(rank)] = Tool_DASP_Result.at[unfounIDIndex,str(rank)][0]

    if Fair:
        Tools_DASP_Result.to_csv('./Results/LabeledData/AllToolsData_Fair.csv',index=False)
    else:
        Tools_DASP_Result.to_csv('./Results/LabeledData/AllToolsData.csv',index=False)
   
    return Tools_DASP_Result

#electLabel(['All'])