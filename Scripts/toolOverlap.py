import pandas as pd
from ast import literal_eval
import seaborn as sns
import matplotlib.pyplot as plt
from Scripts.commonSamples import get_commonSamples

def getOverlap(tools,Fair):
    try:
        if len(tools) <= 1:
            print('You should pass a list of tools')
        else:
            overlapDF = pd.DataFrame(index=tools, columns=tools)

            ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP',index_col='Tool')

            if Fair:
                #Git common addr
                commonAdrr = pd.DataFrame()
                commonAdrr['contractAddress'] =  get_commonSamples(tools)

            for tool in tools:
                baseTool_Labels = pd.read_csv('./Results/LabeledData/'+tool+'.csv',converters={tool+'_DASP_Rank': literal_eval})

                if Fair:
                    #remove none common addr
                    baseTool_Labels.drop(baseTool_Labels[~baseTool_Labels['contractAddress'].isin(commonAdrr['contractAddress'])].index, inplace=True)

                for test in tools:
                    if test == tool:
                        overlapDF.at[tool,test] = (1/1) * 100
                    else:
                        vulnList = get_common_vuln_list(tool,test,ToolsCapacity)
    
                        if len(vulnList)>0:
                            testTool_Labels = pd.read_csv('./Results/LabeledData/'+test+'.csv',converters={test+'_DASP_Rank': literal_eval})
                            overlapDF.at[tool,test] = compute_overlap(tool,test,baseTool_Labels,testTool_Labels,vulnList)
                            
                            if Fair:
                                #remove none common addr
                                testTool_Labels.drop(testTool_Labels[~testTool_Labels['contractAddress'].isin(commonAdrr['contractAddress'])].index, inplace=True)
                        else:
                            overlapDF.at[tool,test] = 0*100
            plot_Overlep_HeatMap(overlapDF)
            if Fair:
               overlapDF.to_csv('./Results/Overlap/OverlapDegree_Fair.csv') 
            else:
                overlapDF.to_csv('./Results/Overlap/OverlapDegree.csv')
        return overlapDF
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
def compute_overlap(tool,test,baseTool_Labels,testTool_Labels,vulnList):
    overlapValue = 0
    base_totalSamples = 0
    equalFlags = 0

    for index, row in baseTool_Labels.iterrows():
        baseLabel = baseTool_Labels.at[index,tool+'_DASP_Rank']

        if len(list(set(baseLabel) & set(vulnList)))== 0 or 'error' in baseLabel:
            continue
        else:
            ID = baseTool_Labels.at[index,'contractAddress']
            if testTool_Labels.query("contractAddress == @ID").shape[0] > 0:
                Test_RowIndex = testTool_Labels.query("contractAddress == @ID").index[0]
                testLabel = testTool_Labels.at[Test_RowIndex,test+'_DASP_Rank']

                base_totalSamples += len(baseLabel)
                equalFlags += len(list(set(baseLabel) & set(testLabel)))

    if equalFlags > 0:
        overlapValue = (equalFlags / base_totalSamples) 

    return overlapValue * 100

def get_common_vuln_list(tool, test,ToolsCapacity):
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack']
    vulnList = []
    for v in range(0, len(DASP_Labels)):
        if ToolsCapacity.at[tool,DASP_Labels[v]] == ToolsCapacity.at[test,DASP_Labels[v]] == 1:
            vulnList.append(v+1)
    return vulnList

def plot_Overlep_HeatMap(overlapDF):
    overlapDF = overlapDF.astype(float)
    ax = sns.heatmap(overlapDF, annot=True, fmt='.2f',cmap='Blues',vmax=100,vmin=0,linewidths=1,square=True,annot_kws={'size': 12,'weight':'bold'})
    plt.title("Overlap of Tool Findings %")
    ax.invert_yaxis()
    plt.show() 

#getOverlap(['MAIAN','Mythril','Semgrep','Slither','Solhint','VeriSmart'])