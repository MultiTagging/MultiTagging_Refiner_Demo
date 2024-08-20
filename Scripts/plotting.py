import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import os

def plot_result(tool,Base, Fair):
    try:
        if Fair:
            EvaluationsFolderPath = './Results/Evaluations_Fair/'
        else:
            EvaluationsFolderPath = './Results/Evaluations/'
        ToolsCapacity = pd.read_excel('./Mapping/ToolsCapacity.xlsx',sheet_name='DASP',index_col='Tool')
        labels = []
        if len(Base) == 1 and Base[0].lower() == 'all':
            Base = [f.name for f in os.scandir(EvaluationsFolderPath) if f.is_dir()]     
        if len(tool) == 1 and tool[0].lower() == 'all':
            tool = [f.name.split('.')[0] for f in os.scandir(EvaluationsFolderPath+Base[0]) if f.is_file() and '.csv' in f.name]
        tool = sorted(tool)
        Base = sorted(Base)
        resultDF= get_performance_results(tool,Base,Fair)
        plot_performance_results(resultDF,tool,ToolsCapacity)
        
        return resultDF
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise

def get_labelsList(ToolsCapacity):
    labels = []
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation','Short Address Attack']
    for v in DASP_Labels:
        if 1 in ToolsCapacity[v].tolist():
            labels.append(v)
    return labels

def plot_performance_results(resultDF,tool,ToolsCapacity):
    Base = resultDF.Base.unique().tolist()

    if len(tool) > 1 and len(Base) > 1:   # Many tools x Many Bases
        plot_ManyTool_ManyBase(resultDF,tool,ToolsCapacity)
    elif len(tool)== 1 and len(Base) > 1: # One tool x Many Bases >> ToBeAdded
        print(len(resultDF))
    elif len(tool)> 1 and len(Base) == 1: # Many tools x One Base
        plot_ManyTool_OneBase(resultDF,tool,ToolsCapacity)
    else:                                 # One tool x One Base
        plot_OneTool_OneBase(resultDF,tool)

def plot_ManyTool_ManyBase(resultDF,tool,ToolsCapacity):
    Base = resultDF.Base.unique().tolist()
    Vulnerabilities = get_labelsList(ToolsCapacity)

    dict_resultDF = resultDF.to_dict('records')
    rows = len(Vulnerabilities)
    cols = len(Base)
    fig, axs = plt.subplots(rows,cols, figsize=(25, 30))
    plt.rc('xtick', labelsize='large')
    plt.rc('ytick', labelsize=6)

    for v in Vulnerabilities:
        for b in Base:
            if (b =='Doublade' and Vulnerabilities.index(v)+1 not in [1,2,4,5]) or (b =='SolidiFI' and Vulnerabilities.index(v)+1 not in [1,2,3,4,7,8]):
                axs[Vulnerabilities.index(v),Base.index(b)].axis('off')
            else:
                Precision_Scores = []
                Recall_Scores = []
                #store Precision and Recall in one list
                for index in range(0,len(dict_resultDF)):
                    
                    if dict_resultDF[index]['Base'] == b and dict_resultDF[index]['Label'] == v:
                        for t in tool:
                            Precision_Scores.append(dict_resultDF[index][t+'_Precision'])
                            Recall_Scores.append(dict_resultDF[index][t+'_Recall'])
                        continue
                # Plot bar chart
                bar_width = 0.4
                x_range_Precision_Scores = [idx - 0.2 for idx in range(len(tool))]
                x_range_Recall_Scores = [idx for idx in range(len(tool))]

                axs[Vulnerabilities.index(v),Base.index(b)].bar(x_range_Precision_Scores,Precision_Scores,width=bar_width,color='lightblue')
                axs[Vulnerabilities.index(v),Base.index(b)].bar(x_range_Recall_Scores,Recall_Scores,width=bar_width,color='steelblue')
                axs[Vulnerabilities.index(v),Base.index(b)].grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
                axs[Vulnerabilities.index(v),Base.index(b)].grid(True, color="grey", which='minor', linestyle=':', linewidth="0.5")
                axs[Vulnerabilities.index(v),Base.index(b)].minorticks_on()
                axs[Vulnerabilities.index(v),Base.index(b)].set_yticks((0,0.5,1))
                ax = axs[Vulnerabilities.index(v),Base.index(b)]
                for p in ax.patches:
                    if p.get_height() > 0:
                        ax.text(p.get_x()+0,
                        p.get_height()* .5 ,
                        '{0:.2f}'.format(p.get_height()),
                        color='black', rotation='vertical', size='small')
                
                axs[Vulnerabilities.index(v),Base.index(b)].set_ylabel(v, rotation=90,fontsize=7)
                axs[Vulnerabilities.index(v),Base.index(b)].set_xticks(range(len(tool)))
                axs[Vulnerabilities.index(v),Base.index(b)].set_xticklabels(tool,rotation = 30,fontsize=7)
                
    pad = 5
    for ax, col in zip(axs[0], Base):
        ax.annotate(col,xy=(0.5, 1), xytext=(0, pad),
                xycoords='axes fraction', textcoords='offset points',
                size='large', ha='center', va='baseline')

    fig.legend(["Precision", "Recall"],loc="lower left", ncol=1)
    #fig.subplots_adjust(left=0, top=1)
    fig.tight_layout()
    plt.show()

def plot_ManyTool_OneBase(resultDF,tool,ToolsCapacity):
    Base = resultDF.Base.unique().tolist()
    Vulnerabilities = get_labelsList(ToolsCapacity)

    dict_resultDF = resultDF.to_dict('records')
    rows = cols =3

    fig, axs = plt.subplots(rows,cols, figsize=(15, 13))
    plt.rc('xtick', labelsize=10)
    plt.rc('ytick', labelsize=10)
    x=y=0
    for v in Vulnerabilities:
        Precision_Scores = []
        Recall_Scores = []

        #store Precision and Recall in one list
        for index in range(0,len(dict_resultDF)):
            if dict_resultDF[index]['Label'] == v:
                #print('b is:', b, 'and Base is:', dict_resultDF[index]['Base'])
                for t in tool:
                    Precision_Scores.append(dict_resultDF[index][t+'_Precision'])
                    Recall_Scores.append(dict_resultDF[index][t+'_Recall'])
                continue
        # Plot bar chart
        bar_width = 0.4
        x_range_Precision_Scores = [idx - bar_width/2 for idx in range(len(tool))]
        x_range_Recall_Scores = [idx + bar_width/2 for idx in range(len(tool))]

        axs[x,y].bar(x_range_Precision_Scores,Precision_Scores,width=bar_width,color='lightblue')
        axs[x,y].bar(x_range_Recall_Scores,Recall_Scores,width=bar_width,color='steelblue')
        axs[x,y].grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
        axs[x,y].grid(True, color="grey", which='minor', linestyle=':', linewidth="0.5")
        axs[x,y].minorticks_on()
        axs[x,y].set_yticks((0,0.5,1))
        ax = axs[x,y]
        for p in ax.patches:
            if p.get_height() > 0:
                ax.text(p.get_x()+0,
                p.get_height()* .5 ,
                '{0:.2f}'.format(p.get_height()),
                color='black', rotation='vertical', size='large')
        axs[x,y].set_xlabel('Tool')
        axs[x,y].set_ylabel('Score')
        axs[x,y].set_title( v, fontsize=10)
        axs[x,y].set_xticks(range(len(tool)))
        axs[x,y].set_xticklabels(tool,rotation = 75)
        
        if (y+1)%3 == 0:
            y=0
            x +=1
        else:
            y +=1

    fig.legend(["Precision", "Recall"])
    fig.tight_layout()
    axs.flat[-1].set_visible(False)
    
    plt.show()

def plot_OneVuln_ManyTool(Vulnerability,Base,tool,Precision_Recall_scores):
    #create DataFrame
    Precision_Recall_DF = pd.DataFrame({'Tool': tool*2,
                                  'Score': Precision_Recall_scores,
                                  'Evaluation Metrics': ['Precision']*6 + ['Recall']*6})
    #set seaborn plotting aesthetics
    sns.set(style='ticks')
    #create grouped bar charts
    g, axes = plt.subplots(9,3)
    ax = axes[0,0]
    g=sns.catplot(x='Tool', y='Score', hue='Evaluation Metrics', data=Precision_Recall_DF, kind='bar', height=4, aspect=2.5, palette="PuBu")
    
    
    for p in ax.patches:
        ax.text(p.get_x() + 0.15,
                p.get_height()* .5 ,
                '{0:.3f}'.format(p.get_height()),
                color='black', rotation='vertical', size='small')

    plt.title('Tools performance in detecting '+ Vulnerability + ' on ' + Base + ' dataset', fontsize=12)
    plt.grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
    plt.grid(True, color="grey", which='minor', linestyle=':', linewidth="0.5");
    plt.minorticks_on()
    plt.xticks(rotation = 90)
    plt.show()        

def plot_OneTool_OneBase(resultDF,tool):
    Base = resultDF.Base.unique().tolist()
    #store Precision and Recall in one list
    Precision_Recall_scores =[]
    Precision_Scores = resultDF[tool[0]+'_Precision'].to_list()
    Recall_Scores  = resultDF[tool[0]+'_Recall'].to_list()

    Precision_Recall_scores = Precision_Scores + Recall_Scores
    NoOfLabels = len(resultDF)
    #create DataFrame
    Precision_Recall_And_DF = pd.DataFrame({'Vulnerability': resultDF['Label'].to_list()*2,
                                  'Score': Precision_Recall_scores,
                                  'Evaluation Metrics': ['Precision']*NoOfLabels + ['Recall']*NoOfLabels})
    
    #set seaborn plotting aesthetics
    sns.set(style='ticks')
    #create grouped bar chart
    g=sns.catplot(x='Vulnerability', y='Score', hue='Evaluation Metrics', data=Precision_Recall_And_DF, kind='bar', height=4, aspect=2.5, palette="PuBu")

    ax = g.facet_axis(0,0)
    for p in ax.patches:
        ax.text(p.get_x() + 0.15,
                p.get_height()* .5 ,
                '{0:.2f}'.format(p.get_height()),
                color='black', rotation='vertical', size='small')

    plt.title('Precision and Recall for ' + tool[0] + ' per vulnerability on ' + Base[0], fontsize=12)
    plt.grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
    plt.grid(True, color="grey", which='minor', linestyle=':', linewidth="0.5");
    plt.minorticks_on()
    plt.xticks(rotation = 90)
    plt.show()

def get_performance_results(tool,Base,Fair):
    resultDF = buildDF(tool)
    if Fair:
        EvaluationsFolderPath = './Results/Evaluations_Fair/'
    else:
        EvaluationsFolderPath = './Results/Evaluations/'

    for b in Base:
        subResultDF = pd.DataFrame(columns = resultDF.columns.to_list())
        flag = True
        for t in tool:
           toolResult = pd.read_csv(EvaluationsFolderPath+b+'/'+t+'.csv')
           for index, row in toolResult.iterrows():
               if flag: 
                   subResultDF.at[index,'Base'] = toolResult.at[index,'Base'].rsplit('.')[0]
                   subResultDF.at[index,'Label'] = toolResult.at[index,'Label']
                   subResultDF.at[index,'In Base'] = toolResult.at[index,'In Base']
                   
               subResultDF.at[index,'Detectable By ' + t] = toolResult.at[index,'Detectable By Tool']
               subResultDF.at[index,t+'_Recall'] = toolResult.at[index,'Recall']
               subResultDF.at[index,t+'_Precision'] = toolResult.at[index,'Precision']
           flag = False
        resultDF = pd.concat([resultDF,subResultDF])
        resultDF.reset_index(inplace=True, drop=True)
    return resultDF

def buildDF(tool):
    resultDF = pd.DataFrame(columns = ['Base','Label','In Base'])
    for t in tool:
        resultDF['Detectable By ' + t] = ''
        resultDF[t+'_Recall'] = ''
        resultDF[t+'_Precision'] = ''
    return resultDF

#plot_result(['All'],['SolidiFI','Doublade','JiuZhou','SBcurated'])