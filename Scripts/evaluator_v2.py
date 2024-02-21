import pandas as pd
from sklearn import metrics
import matplotlib.pyplot as plt
from matplotlib import gridspec

def eval_v2(tool,base):
    ToolDS = pd.read_csv('./Results/LabeledData/'+tool+'.csv')
    BaseDS = pd.read_csv('./Benchmarks/EDA_Outcomes/BaseDS/' + base)

    predicted = createDASPmetrics(tool,ToolDS)
    actual = createDASPmetrics('Base',BaseDS)

    while len(predicted['id']) != len(actual['id']):
        if len(predicted['id']) > len(actual['id']):
            predicted.drop(predicted[~predicted['id'].isin(actual['id'])].index, inplace=True)    
            predicted.reset_index(inplace=True, drop=True)
        else:
            actual.drop(actual[~actual['id'].isin(predicted['id'])].index, inplace=True)    
            actual.reset_index(inplace=True, drop=True)

    metricsDF = compute_confusion_matrix(actual, predicted)
    print(metricsDF)

def createDASPmetrics(tool,DS):
    DASPmetrics =  pd.DataFrame(columns=['id','DASP','1','2','3','4','5','6','7','8','9'])
    address = ''
    DASP_Label = ''

    if tool == 'Base':
        address = 'fp_sol'
        DASP_Label = 'DASP'
    else:
        address = 'contractAddress'
        DASP_Label = tool+'_DASP_Rank'

    for index, row in DS.iterrows():
        if len(DS.at[index,DASP_Label]) == 1 and 'error' in DS.at[index,DASP_Label]:
            continue
        else:
            DASPmetrics.at[index,'id'] = DS[address].iloc[index]
            DASPmetrics.at[index,'DASP'] = DS[DASP_Label].iloc[index]
            if DS.at[index,DASP_Label] == 'safe':
                for i in range(1,10):
                    DASPmetrics.at[index, str(i)] = 0
            else:
                for i in range(1,10):
                    DASPmetrics.at[index, str(i)] = 1 if str(i) in DS.at[index,DASP_Label] else 0
    DASPmetrics.sort_values('id',inplace=True)
    DASPmetrics.reset_index(inplace=True, drop=True)
    return DASPmetrics

def compute_confusion_matrix(actual, predicted):
    metricsDF = pd.DataFrame(columns = ['Label','TP','TN','FP','FN','Recall','Precision'])
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack']

    for label in range(0,9):
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
    
    return metricsDF

#eval_v2('Slither','cgt_MultiDS_StudySet.csv')