import pandas as pd
from sklearn import metrics

def eval(tool):
    ToolDS = pd.read_csv('./Results/LabeledData/'+tool+'.csv')
    BaseDS = pd.read_csv('./Benchmarks/EDA_Outcomes/mult-label_CGT_DS.csv')

    predicted = createDASPmetrics(tool,ToolDS)
    BaseDS.drop(BaseDS[~BaseDS['fp_sol'].isin(ToolDS['contractAddress'])].index, inplace=True)
    BaseDS.reset_index(inplace=True, drop=True)        
    actual = createDASPmetrics('Base',BaseDS)
    #actual = actual.drop_duplicates(keep='last')
    
    confusionMatrix = metrics.confusion_matrix(actual, predicted)
    print(confusionMatrix)

def createDASPmetrics(tool,DS):
    DASPmetrics =  pd.DataFrame(columns=['id','1','2','3','4','5','6','7','8','9'])
    address = ''
    DASP_Label = ''

    if tool == 'Base':
        address = 'addr'
        DASP_Label = 'DASP'
    else:
        address = 'contractAddress'
        DASP_Label = tool+'_Labels'

    for index, row in DS.iterrows():
        DASPmetrics.at[index,'id'] = DS[address].iloc[index]
        if DS[DASP_Label].iloc[index] == 'safe':
            for i in range(1,10):
                DASPmetrics.at[index, str(i)] = 0
        else:
            for i in range(1,10):
                DASPmetrics.at[index, str(i)] = 1 if str(i) in DS[DASP_Label].iloc[index] else 0
    return DASPmetrics

eval('Solhint')