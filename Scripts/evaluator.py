import pandas as pd
from ast import literal_eval
from pathlib import Path
import json
from Scripts.commonSamples import get_commonSamples
#-------------------------------------------
#Get the correct path to the configuration file
#-------------------------------------------
config_file_name = 'config.json'
self_dir = Path(__file__).resolve().parent
config_file_path = self_dir / config_file_name
#-------------------------------------------
def eval(tool,base,Fair):
    try:
        configFile = open(config_file_path)
        config_File = json.load(configFile)
        configFile.close()
        BaseDS_Dir = config_File['BaseDS'][0]['Path']

        vote = False
        if 'vote' in tool.lower():
            vote = True
            if Fair:
                ToolDS = pd.read_csv('./Results/LabeledData/voteBasedData_Fair.csv',converters={'DASP': literal_eval})
            else:
                ToolDS = pd.read_csv('./Results/LabeledData/voteBasedData.csv',converters={'DASP': literal_eval})
            voteMethod = '_' + tool.rsplit('_')[1]

            DASP_unique_Ranks_tool = detectable_vulnerabilities(ToolDS,True,vote)
            print('The implemented list of tools are able to detect', len(DASP_unique_Ranks_tool), 'vulnerabilities from DASP Top 10, which are:\n', DASP_unique_Ranks_tool)
        
        else:
            DASP_unique_Ranks_tool = detectable_vulnerabilities(tool,False,vote)
            print(tool, 'designed to detect', len(DASP_unique_Ranks_tool), 'vulnerabilities from DASP Top 10, which are:\n', DASP_unique_Ranks_tool)
            ToolDS = pd.read_csv('./Results/LabeledData/'+tool+'.csv',converters={tool+'_DASP_Rank': literal_eval})
            
        BaseDS = pd.read_csv(BaseDS_Dir + base,converters={'DASP': literal_eval})

        if vote:
            predicted = createDASPmetrics(tool,ToolDS,voteMethod)
        else:
            predicted = createDASPmetrics(tool,ToolDS,'')
        actual = createDASPmetrics('Base',BaseDS,'')

        DASP_unique_Ranks_Base = detectable_vulnerabilities(actual,True,vote)
        print(base.split('.')[0], 'contains', len(DASP_unique_Ranks_Base), 'vulnerability types from DASP Top 10, which are:\n', DASP_unique_Ranks_Base)

        if Fair:
            #remove Uncommon samples
            commonAdrr = pd.DataFrame()
            commonAdrr['id'] =  get_commonSamples(['MAIAN','Mythril','Slither','Semgrep','Solhint','VeriSmart'])
            predicted.drop(predicted[~predicted['id'].isin(commonAdrr['id'])].index, inplace=True)
            predicted.reset_index(inplace=True, drop=True)
            
        while len(predicted['id']) != len(actual['id']):
            if len(predicted['id']) > len(actual['id']):
                predicted.drop(predicted[~predicted['id'].isin(actual['id'])].index, inplace=True)    
                predicted.reset_index(inplace=True, drop=True)
            else:
                actual.drop(actual[~actual['id'].isin(predicted['id'])].index, inplace=True)    
                actual.reset_index(inplace=True, drop=True)
        
        metricsDF = compute_confusion_matrix(actual, predicted,DASP_unique_Ranks_Base)
        metricsDF.insert(0, 'Base',base,True)
        metricsDF = add_detectable_Base_Columns(metricsDF,DASP_unique_Ranks_tool,DASP_unique_Ranks_Base)

        #compute avgAnalysisTime and errorRate
        if not vote:
            set_avgAnalysisTimeAndFailureRate(predicted,BaseDS,base.split('.')[0],tool,Fair)
        #-------------------------------------------
        if Fair:
            if vote:
                metricsDF.to_csv('./Results/Evaluations_Fair/'+base.split('.')[0]+'/'+ tool +'.csv',index=False) #toBemove to other dir
                predicted.to_csv('./Results/DASP_Data_Fair/'+base.split('.')[0]+'/predicted_'+tool +'.csv',index=False) #toBemove to other dir
            else:
                metricsDF.to_csv('./Results/Evaluations_Fair/'+base.split('.')[0]+'/' + tool + '.csv',index=False)
                predicted.to_csv('./Results/DASP_Data_Fair/'+base.split('.')[0]+'/predicted_'+tool+'.csv',index=False)
            actual.to_csv('./Results/DASP_Data_Fair/'+base.split('.')[0]+'/actual.csv',index=False)
        else:
            if vote:
                metricsDF.to_csv('./Results/Evaluations/'+base.split('.')[0]+'/'+tool +'.csv',index=False) #toBemove to other dir
                predicted.to_csv('./Results/DASP_Data/'+base.split('.')[0]+'/predicted_'+tool +'.csv',index=False) #toBemove to other dir
            else:
                metricsDF.to_csv('./Results/Evaluations/'+base.split('.')[0]+'/'+tool+'.csv',index=False)
                predicted.to_csv('./Results/DASP_Data/'+base.split('.')[0]+'/predicted_'+tool+'.csv',index=False)
            actual.to_csv('./Results/DASP_Data/'+base.split('.')[0]+'/actual.csv',index=False)

        return metricsDF
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise

def detectable_vulnerabilities(DS,flag,vote):
    DASP_unique_Ranks = []

    if flag: #True if DS is base data or vote data
        if vote:
            DASP_unique_Ranks = list(set(DS['DASP'].sum()))
        else:
            for rank in range(1,11):
                if 1 in DS[str(rank)].tolist():
                    DASP_unique_Ranks.append(rank)
    else:
        VulnerablityMapDF = pd.read_excel('./Mapping/VulnerablityMap.xlsx',sheet_name=DS)
        VulnerablityMapDF.sort_values('DASP',inplace=True)
        DASP_unique_Ranks= VulnerablityMapDF['DASP'].unique()
        DASP_unique_Ranks = list(filter(lambda x: str(x) != 'nan', DASP_unique_Ranks))
    
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']

    DASP_unique_Labels = []
    for rank in DASP_unique_Ranks:
        DASP_unique_Labels.append(DASP_Labels[int(rank-1)])

    return DASP_unique_Labels

def createDASPmetrics(tool,DS,method):
    DASPmetrics =  pd.DataFrame(columns=['id','DASP','1','2','3','4','5','6','7','8','9','10','AnalysisTime'])
    address = ''
    DASP_Label = ''

    if 'vote' in tool.lower():
        DASPmetrics['id'] = DS['id']
        DASPmetrics['DASP'] = DS['DASP']
        for i in range(1,11):
            DASPmetrics[str(i)] = DS[str(i)+method]
    else:
        if tool.lower() == 'base':
            address = 'fp_sol'
            DASP_Label = 'DASP'
        else:
            address = 'contractAddress'
            DASP_Label = tool+'_DASP_Rank'

        for index, row in DS.iterrows():
            if ['error'] == DS.at[index,DASP_Label]:
                continue
            else:
                DASPmetrics.at[index,'id'] = DS[address].iloc[index]
                DASPmetrics.at[index,'DASP'] = DS[DASP_Label].iloc[index]
                if tool !='Base':
                    DASPmetrics.at[index,'AnalysisTime'] = DS[tool+'_AnalysisTime'].iloc[index]
                if DS.at[index,DASP_Label] == 'safe':
                    for i in range(1,11):
                        DASPmetrics.at[index, str(i)] = 0
                else:
                    for i in range(1,11):
                        DASPmetrics.at[index, str(i)] = 1 if i in DS.at[index,DASP_Label] else 0
    DASPmetrics.sort_values('id',inplace=True)
    DASPmetrics.reset_index(inplace=True, drop=True)
    return DASPmetrics

def compute_confusion_matrix(actual, predicted,DASP_unique_Ranks_Base):
    metricsDF = pd.DataFrame(columns = ['Label','Base Size','Positive No','Coverage','TP','TN','FP','FN','Recall','Precision'])
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack','Unknown Unknowns']

    for label in range(0,10):
        if label in [8,9] or not DASP_Labels[label] in DASP_unique_Ranks_Base:
            continue

        TP = TN = FP = FN = 0
        for index, rwo in actual.iterrows():
            if actual.at[index,'id'] == predicted.at[index,'id']:
                if actual.at[index,str(label +1)] == 0 and predicted.at[index,str(label +1)] == 0:
                    TN +=1
                elif actual.at[index,str(label +1)] == 1 and predicted.at[index,str(label +1)] == 1:
                    TP += 1
                elif actual.at[index,str(label +1)] == 0 and predicted.at[index,str(label +1)] == 1:
                    FP += 1
                elif actual.at[index,str(label +1)] == 1 and predicted.at[index,str(label +1)] == 0:
                    FN += 1
            else:
                print(actual.at[index,'id'], ' And ', predicted.at[index,'id'], ' are not equal')
        metricsDF.at[label,'Label'] = DASP_Labels[label]
        metricsDF.at[label,'TP'] = TP
        metricsDF.at[label,'TN'] = TN
        metricsDF.at[label,'FP'] = FP
        metricsDF.at[label,'FN'] = FN

        if (TP+FN) != 0:
            metricsDF.at[label,'Recall'] = (TP/(TP+FN))
        if (TP+FP) != 0:
            metricsDF.at[label,'Precision'] = (TP/(TP+FP))

        metricsDF.at[label,'Base Size'] = len(actual[str(label +1)].tolist())
        metricsDF.at[label,'Positive No'] = actual[str(label +1)].tolist().count(1)
        metricsDF.at[label,'Coverage'] = TP/metricsDF.at[label,'Positive No'] * 100

    return metricsDF

def add_detectable_Base_Columns(metricsDF,DASP_unique_Ranks_tool,DASP_unique_Ranks_Base):
    metricsDF.insert(2, 'In Base','',True)
    metricsDF.insert(3, 'Detectable By Tool','',True)

    for index,row in metricsDF.iterrows():
        metricsDF.at[index, 'In Base'] = True if metricsDF.at[index, 'Label'] in DASP_unique_Ranks_Base else False
        metricsDF.at[index, 'Detectable By Tool'] = True if metricsDF.at[index, 'Label'] in DASP_unique_Ranks_tool else False
    
    return metricsDF

#compute avgAnalysisTime and errorRate
def set_avgAnalysisTimeAndFailureRate(predicted,BaseDS,base,tool,Fair):
    if Fair:
        avgAnalysisTimeAndFailureRateDF = pd.read_csv('./Results/Performance/avgAnalysisTimeAndFailureRate_Fair.csv')
    else:
        avgAnalysisTimeAndFailureRateDF = pd.read_csv('./Results/Performance/avgAnalysisTimeAndFailureRate.csv')
   
    rowIndex =  avgAnalysisTimeAndFailureRateDF.index[(avgAnalysisTimeAndFailureRateDF['Tool'] == tool) & (avgAnalysisTimeAndFailureRateDF['Base'] == base)].to_list()[0]
    #print(rowIndex)
    avgAnalysisTime = predicted[['AnalysisTime']].mean()
    maxAnalysisTime = predicted[['AnalysisTime']].max()
    minAnalysisTime = predicted[['AnalysisTime']].min()
    print('avgAnalysisTime:', avgAnalysisTime[0])
    #print("avgAnalysisTimeAndFailureRateDF.at[rowIndex,'avgAnalysisTime']",avgAnalysisTimeAndFailureRateDF.at[rowIndex,'avgAnalysisTime'])

    avgAnalysisTimeAndFailureRateDF.at[rowIndex,'avgAnalysisTime'] = avgAnalysisTime[0]
    avgAnalysisTimeAndFailureRateDF.at[rowIndex,'maxAnalysisTime'] = maxAnalysisTime[0]
    avgAnalysisTimeAndFailureRateDF.at[rowIndex,'minAnalysisTime'] = minAnalysisTime[0]
    

    FailureRate = ((len(BaseDS) - len(predicted)) / len(BaseDS)) * 100
    print('errorRate: ', FailureRate)

    avgAnalysisTimeAndFailureRateDF.at[rowIndex,'FailureRate'] = FailureRate
    

    if Fair:
        avgAnalysisTimeAndFailureRateDF.to_csv('./Results/Performance/avgAnalysisTimeAndFailureRate_Fair.csv',index=False)
    else:
        avgAnalysisTimeAndFailureRateDF.to_csv('./Results/Performance/avgAnalysisTimeAndFailureRate.csv',index=False)

#eval('vote_avg','eThor.csv')
