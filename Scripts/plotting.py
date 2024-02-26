import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import os

def plot_result(tool,Base):
    EvaluationsFolderPath = './Results/Evaluations/'
    if len(Base) == 1 and Base[0].lower() == 'all':
        Base = [f.name for f in os.scandir(EvaluationsFolderPath) if f.is_dir()]     
    if len(tool) == 1 and tool[0].lower() == 'all':
        tool = [f.name.split('.')[0] for f in os.scandir(EvaluationsFolderPath+Base[0]) if f.is_file()]
    tool = sorted(tool)
    Base = sorted(Base)
    resultDF= get_performance_results(tool,Base)
    plot_performance_results(resultDF,tool)
    
    return resultDF
    

def plot_performance_results(resultDF,tool):
    Base = resultDF.Base.unique().tolist()

    if len(tool) > 1 and len(Base) > 1:   # Many tools x Many Bases >> Done
        plot_ManyTool_ManyBase(resultDF,tool)
    elif len(tool)== 1 and len(Base) > 1: # One tool x Many Bases >> ToBeAdded
        print(len(resultDF))
    elif len(tool)> 1 and len(Base) == 1: # Many tools x One Base >> ToBeAdded
        print(len(resultDF))
    else:                                 # One tool x One Base >> Done
        plot_OneTool_OneBase(resultDF,tool)

def plot_ManyTool_ManyBase(resultDF,tool):
    Base = resultDF.Base.unique().tolist()
    Vulnerabilities = resultDF.Label.unique().tolist()

    dict_resultDF = resultDF.to_dict('records')
    rows = len(Vulnerabilities)
    cols = len(Base)

    fig, axs = plt.subplots(rows,cols, figsize=(25, 20))
    plt.rc('xtick', labelsize='large')
    plt.rc('ytick', labelsize=6)

    for v in Vulnerabilities:
        for b in Base:
            Precision_Scores = []
            Recall_Scores = []
            #store Precision and Recall in one list
            for index in range(0,len(dict_resultDF)):
                
                if dict_resultDF[index]['Base'] == b and dict_resultDF[index]['Label'] == v:
                    #print('b is:', b, 'and Base is:', dict_resultDF[index]['Base'])
                    for t in tool:
                        Precision_Scores.append(dict_resultDF[index][t+'_Precision'])
                        Recall_Scores.append(dict_resultDF[index][t+'_Recall'])
                    continue
            # Plot bar chart
            bar_width = 0.4
            x_range_Precision_Scores = [idx - bar_width/2 for idx in range(len(tool))]
            x_range_Recall_Scores = [idx + bar_width/2 for idx in range(len(tool))]
            axs[Vulnerabilities.index(v),Base.index(b)].bar(x_range_Precision_Scores,Precision_Scores,width=bar_width,color='lightblue')
            axs[Vulnerabilities.index(v),Base.index(b)].bar(x_range_Recall_Scores,Recall_Scores,width=bar_width,color='steelblue')
            axs[Vulnerabilities.index(v),Base.index(b)].grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
            axs[Vulnerabilities.index(v),Base.index(b)].grid(True, color="grey", which='minor', linestyle=':', linewidth="0.5")
            axs[Vulnerabilities.index(v),Base.index(b)].minorticks_on()
            axs[Vulnerabilities.index(v),Base.index(b)].set_yticks((0,0.5,1))
            ax = axs[Vulnerabilities.index(v),Base.index(b)]
            for p in ax.patches:
                if p.get_height() > 0:
                    ax.text(p.get_x()+0.1,
                    p.get_height()* .5 ,
                    '{0:.2f}'.format(p.get_height()),
                    color='black', rotation='vertical', size='large')
            #axs[Vulnerabilities.index(v),Base.index(b)].set_xlabel('Tool')
            #axs[Vulnerabilities.index(v),Base.index(b)].set_ylabel('Score')
            #axs[Vulnerabilities.index(v),Base.index(b)].set_title('Tools performance in detecting '+ v + ' on ' + b + ' dataset', fontsize=6)
            
            if Vulnerabilities.index(v) == len(Vulnerabilities) -1 :
                axs[Vulnerabilities.index(v),Base.index(b)].set_xticks(range(len(tool)))
                axs[Vulnerabilities.index(v),Base.index(b)].set_xticklabels(tool,rotation = 90)
            else:
                axs[Vulnerabilities.index(v),Base.index(b)].set_xticks(range(len(tool)))
                axs[Vulnerabilities.index(v),Base.index(b)].set_xticklabels([])
    pad = 5
    for ax, col in zip(axs[0], Base):
        ax.annotate(col,xy=(0.5, 1), xytext=(0, pad),
                xycoords='axes fraction', textcoords='offset points',
                size='large', ha='center', va='baseline')
    for ax, row in zip(axs[:,0], Vulnerabilities):
        ax.annotate(row, xy=(0, 0.5), xytext=(-ax.yaxis.labelpad - pad, 0),
                xycoords=ax.yaxis.label, textcoords='offset points',
                size=10, ha='right', va='center')

    fig.legend(["Precision", "Recall"])
    #fig.supylabel('Score')
    #fig.tight_layout()
    fig.subplots_adjust(left=0.15, top=0.95)
    
    plt.show()

        
def plot_OneVuln_ManyTool(Vulnerability,Base,tool,Precision_And_Recall_scores):
    #create DataFrame
    Precision_And_Recall_scores_DF = pd.DataFrame({'Tool': tool*2,
                                  'Score': Precision_And_Recall_scores,
                                  'Evaluation Metrics': ['Precision']*6 + ['Recall']*6})
    #set seaborn plotting aesthetics
    sns.set(style='ticks')
    #create grouped bar chart
    g, axes = plt.subplots(9,3)
    ax = axes[0,0]
    g=sns.catplot(x='Tool', y='Score', hue='Evaluation Metrics', data=Precision_And_Recall_scores_DF, kind='bar', height=4, aspect=2.5, palette="PuBu")
    
    
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
    Precision_And_Recall_scores =[]
    Precision_Scores = resultDF[tool[0]+'_Precision'].to_list()
    Recall_Scores  = resultDF[tool[0]+'_Recall'].to_list()
    Precision_And_Recall_scores = Precision_Scores + Recall_Scores
    
    #create DataFrame
    Precision_And_Recall_scores_DF = pd.DataFrame({'Vulnerability': resultDF['Label'].to_list()*2,
                                  'Score': Precision_And_Recall_scores,
                                  'Evaluation Metrics': ['Precision']*9 + ['Recall']*9})
    
    #set seaborn plotting aesthetics
    sns.set(style='ticks')
    #create grouped bar chart
    g=sns.catplot(x='Vulnerability', y='Score', hue='Evaluation Metrics', data=Precision_And_Recall_scores_DF, kind='bar', height=4, aspect=2.5, palette="PuBu")

    ax = g.facet_axis(0,0)
    for p in ax.patches:
        ax.text(p.get_x() + 0.15,
                p.get_height()* .5 ,
                '{0:.3f}'.format(p.get_height()),
                color='black', rotation='vertical', size='small')

    plt.title('Precision and Recall for ' + tool[0] + 'tool per vulnerability on ' + Base[0], fontsize=12)
    plt.grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
    plt.grid(True, color="grey", which='minor', linestyle=':', linewidth="0.5");
    plt.minorticks_on()
    plt.xticks(rotation = 90)
    plt.show()

def get_performance_results(tool,Base):
    resultDF = buildDF(tool)
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

#plot_result(['All'],['All'])