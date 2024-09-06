import pandas as pd
from ast import literal_eval
import seaborn as sns
import matplotlib.pyplot as plt
from Scripts.commonSamples import get_commonSamples
import os

DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack']

def getOverlapPerV(tools,Fair):
    try:
        if len(tools) <= 1 and tools[0].lower() != 'all':
            print('You should pass a list of tools')
        else:
            if tools[0].lower() == 'all':
                tools = sorted([f.name.split('.')[0] for f in os.scandir('./Results/LabeledData') if f.is_file() and 'csv' in f.name and not f.name in ['voteBasedData.csv','AllToolsData.csv','voteBasedData_Fair.csv','AllToolsData_Fair.csv']])
            if Fair:
                #Git common addr
                commonAdrr = pd.DataFrame()
                commonAdrr['contractAddress'] =  get_commonSamples(tools)
            
            ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP',index_col='Tool')
            overlapDF = pd.DataFrame(columns=['vulnerability','Baseline'] + tools)
            index = 0
            for tool in tools:
                baseTool_Labels = pd.read_csv('./Results/LabeledData/'+tool+'.csv',converters={tool+'_DASP_Rank': literal_eval})
                if Fair:
                    #remove none common addr
                    baseTool_Labels.drop(baseTool_Labels[~baseTool_Labels['contractAddress'].isin(commonAdrr['contractAddress'])].index, inplace=True)
                    baseTool_Labels.reset_index(inplace=True,drop=True)

                last = len(overlapDF)
                for test in tools:
                    hop = 0
                    if test != tool:
                        vulnList = get_common_vuln_list(tool,test,ToolsCapacity)
                        testTool_Labels = pd.read_csv('./Results/LabeledData/'+test+'.csv',converters={test+'_DASP_Rank': literal_eval})
                        if Fair:
                            #remove none common addr
                            testTool_Labels.drop(testTool_Labels[~testTool_Labels['contractAddress'].isin(commonAdrr['contractAddress'])].index, inplace=True)
                            testTool_Labels.reset_index(inplace=True,drop=True)
                    for v in DASP_Labels:
                        if DASP_Labels.index(v)+1 in [9]:
                            continue
                        index = last + hop
                        overlapDF.at[index,'vulnerability'] = v
                        overlapDF.at[index,'Baseline'] = tool
                        if test != tool:
                            if DASP_Labels.index(v)+1 in vulnList:
                                overlapDF.at[index,test] = compute_overlap(tool,test,baseTool_Labels,testTool_Labels,[DASP_Labels.index(v)+1])
                            else:
                                overlapDF.at[index,test] = 0*100
                        else:
                            overlapDF.at[index,test] = (1/1) * 100
                        hop += 1
            if Fair:
                overlapDF.to_csv('./Results/Overlap/OverlapDegree_PerVuln_Fair.csv',index=False)
            else:
                overlapDF.to_csv('./Results/Overlap/OverlapDegree_PerVuln.csv',index=False)
            plot_Overlep_perVuln_HeatMap(overlapDF,Fair)
            #print(overlapDF)
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

                base_totalSamples += 1 #len(baseLabel)
                if len(list(set(testLabel) & set(vulnList)))>0:
                    equalFlags += 1 #len(list(set(baseLabel) & set(testLabel)))

    if equalFlags > 0:
        overlapValue = (equalFlags / base_totalSamples) 

    return overlapValue * 100

def get_common_vuln_list(tool, test,ToolsCapacity):
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

def plot_Overlep_perVuln_HeatMap(overlapDF,Fair):
    #OverlapDegree_PerVuln = overlapDF
    if Fair:
        OverlapDegree_PerVuln= pd.read_csv('./Results/Overlap/OverlapDegree_PerVuln_Fair.csv')
    else:
        OverlapDegree_PerVuln= pd.read_csv('./Results/Overlap/OverlapDegree_PerVuln.csv')
    Vulnerabilities = OverlapDegree_PerVuln.vulnerability.unique().tolist()

    rows =2
    cols =4
    #fig, axs = plt.subplots(rows,cols)
    fig, axs = plt.subplots(rows,cols, figsize=(15, 8))
    
    index_vuln = 0

    cbar_ax = fig.add_axes([1, 0.12, .01, 0.75])
    
    sns.set(font_scale=1)

    for i,ax in enumerate(axs.flat):
        # get vulnerability data
        overlapDF_perv = OverlapDegree_PerVuln.loc[OverlapDegree_PerVuln['vulnerability'] == Vulnerabilities[index_vuln]]
        overlapDF_perv = overlapDF_perv.drop(['vulnerability'], axis=1)
        overlapDF_perv.set_index('Baseline', inplace=True)
        
        overlapDF_perv = overlapDF_perv.astype(float)

        g=sns.heatmap(overlapDF_perv, cbar=i == 0,cbar_ax=None if i else cbar_ax, annot=True, fmt='.2f',cmap='Blues',vmax=100,vmin=0,linewidths=.1,annot_kws={'size': 12,'weight':'bold'},ax=ax) #square=True,
        #sns.heatmap(overlapDF_perv,cbar_ax=None, annot=True, fmt='.2f',cmap='Blues',vmax=100,vmin=0,linewidths=.1,square=True,annot_kws={'size': 8},ax=ax)

        ax.set(title=Vulnerabilities[index_vuln], xlabel=None, ylabel=None)
        ax.invert_yaxis()
        g.set_yticklabels(g.get_yticklabels(), rotation = 90, fontsize = 10)
        g.set_xticklabels(g.get_xticklabels(), rotation = 0, fontsize = 10)
        index_vuln +=1
        if index_vuln == len(Vulnerabilities):
            break
    #plt.rc('xtick', labelsize=0.5)
    #plt.rc('ytick', labelsize=0.5)
    #fig.tight_layout(rect=[0, 0, .9, .1])
    #axs.flat[-1].set_visible(False)
    #plt.subplots_adjust(hspace = 0,wspace=0.3)
    fig.tight_layout()
    #fig.subplots_adjust(left=.10, top=0.99)
    #fig.subplots_adjust(right=0.10)
    plt.show()

#plot_Overlep_perVuln_HeatMap()
#getOverlapPerV(['MAIAN','Mythril','Semgrep','Slither','Solhint','VeriSmart'])