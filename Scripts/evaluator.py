import pandas as pd
from sklearn import metrics
import matplotlib.pyplot as plt
from matplotlib import gridspec

def eval(tool,base):
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

    predicted.drop('id', axis=1, inplace=True)
    actual.drop('id',axis=1, inplace=True)

    print('Predicted Shape: ', predicted.shape)
    print('Actual Shape: ', actual.shape)

    predicted = predicted.values.tolist()
    actual = actual.values.tolist()

    confusionMatrix = metrics.multilabel_confusion_matrix(actual, predicted)
    plot_confusionMatrix(confusionMatrix, tool)

    from sklearn.metrics import classification_report

    print(classification_report(actual, predicted,zero_division=0))

    from sklearn.metrics import precision_recall_fscore_support as score
    precision,recall,fscore,support=score(actual,predicted,average='weighted')
    print ('Precision : {}'.format(precision))
    print ('Recall    : {}'.format(recall))
    print ('F-score   : {}'.format(fscore))

def createDASPmetrics(tool,DS):
    DASPmetrics =  pd.DataFrame(columns=['id','1','2','3','4','5','6','7','8','9'])
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
            if DS[DASP_Label].iloc[index] == 'safe':
                for i in range(1,10):
                    DASPmetrics.at[index, str(i)] = 0
            else:
                for i in range(1,10):
                    DASPmetrics.at[index, str(i)] = 1 if str(i) in DS[DASP_Label].iloc[index] else 0
        
    DASPmetrics.sort_values('id',inplace=True)
    DASPmetrics.reset_index(inplace=True, drop=True)
    return DASPmetrics

def plot_confusionMatrix(confusionMatrix,tool):
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack']
    
    n_plots=len(confusionMatrix)
    fig, axes = plt.subplots(nrows=3, ncols=3, figsize=(25,15))

    for i, ax in enumerate(axes.flatten()):
        if i < n_plots :
            confusionMatrix_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusionMatrix[i], display_labels = [True,False])
            confusionMatrix_display.plot(ax=ax,cmap=plt.cm.Blues)
            confusionMatrix_display.ax_.set_title(DASP_Labels[i],size=10)
            confusionMatrix_display.im_.colorbar.remove()
    fig.suptitle("Confusion Matrices of " + tool + ' Tool', size=16, y=0.93)
    plt.subplots_adjust(wspace=0.10, hspace=0.5)
    fig.colorbar(confusionMatrix_display.im_, ax=axes)
    plt.show()

#eval('Solhint')