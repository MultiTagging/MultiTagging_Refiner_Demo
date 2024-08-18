import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def get_toolEfficiency(Fair):
    DASP_Labels = ['Reentrancy','Access Control','Arithmetic','Unchecked Return Values','DoS','Bad Randomness','Front-Running','Time manipulation']
    try:

        if Fair:
            avgAnalysisTimeAndFailureRateDF = pd.read_csv('./Results/Performance/avgAnalysisTimeAndFailureRate_Fair.csv')
        else:
            avgAnalysisTimeAndFailureRateDF = pd.read_csv('./Results/Performance/avgAnalysisTimeAndFailureRate.csv')

        Tools = avgAnalysisTimeAndFailureRateDF['Tool'].unique().tolist()
        Bases = avgAnalysisTimeAndFailureRateDF['Base'].unique().tolist()

        coverageScores = get_coverage_scores(Fair,DASP_Labels,Tools)

        rows = 1
        cols =3
        fig=plt.figure(figsize=(12,5))
        plt.style.use('seaborn-v0_8-muted')
        plt.rc('xtick', labelsize=8)
        plt.rc('ytick', labelsize=8)
        count =0

        # Plot avgAnalysisTime
        count += 1
        fig.add_subplot(rows, cols, count) #add empty subplot

        for base in Bases:
            avgAnalysisTime = []
            for tool in Tools:
                rowIndex =  avgAnalysisTimeAndFailureRateDF.index[(avgAnalysisTimeAndFailureRateDF['Tool'] == tool) & (avgAnalysisTimeAndFailureRateDF['Base'] == base)].to_list()[0]
                avgAnalysisTime.append(avgAnalysisTimeAndFailureRateDF.at[rowIndex,'avgAnalysisTime'])            
            
            g = sns.lineplot(x=Tools,y=avgAnalysisTime,marker='o')

        g.set_xticklabels(labels=Tools, rotation=30)
        plt.xlabel('Analysis Tools',fontsize = 10)
        plt.ylabel('avgAnalysisTime (Seconds)',fontsize = 10)            
        plt.title('Average Analysis Time For Each Tool',fontsize = 10)
        plt.grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
        plt.grid(True, color="grey", which='minor', linestyle=':', linewidth="0.3");
        #plt.legend(fontsize = 10)
        
        # Plot FailureRate
        count += 1
        fig.add_subplot(rows, cols, count) #add empty subplot

        for base in Bases:
            FailureRate = []
            for tool in Tools:
                rowIndex =  avgAnalysisTimeAndFailureRateDF.index[(avgAnalysisTimeAndFailureRateDF['Tool'] == tool) & (avgAnalysisTimeAndFailureRateDF['Base'] == base)].to_list()[0]
                FailureRate.append(avgAnalysisTimeAndFailureRateDF.at[rowIndex,'FailureRate'])
            
            g = sns.lineplot(x=Tools,y=FailureRate,marker='o')
        
        g.set_xticklabels(labels=Tools, rotation=30)
        g.set_yticks((0,20,40,60,80,100))
        plt.xlabel('Analysis Tools',fontsize = 10)
        plt.ylabel('FailureRate %',fontsize = 10)            
        plt.title('Failure Rate Of Analysis Tools',fontsize = 10)
        plt.grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
        plt.grid(True, color="grey", which='minor', linestyle=':', linewidth="0.3");
        
        # Plot coverage
        count += 1
        fig.add_subplot(rows, cols, count) #add empty subplot

        g = sns.lineplot(data=coverageScores,marker='o')
        g.set_xticks(np.arange(len(Tools)))
        g.set_xticklabels(labels=Tools, rotation=30)
        
        plt.xlabel('Analysis Tools',fontsize = 10)
        plt.ylabel('Coverage %',fontsize = 10)            
        plt.title('Analysis Tools Coverage',fontsize = 10)
        plt.grid(True, color = "grey", which='major', linewidth = "0.3", linestyle = "-.")
        plt.grid(True, color="grey", which='minor', linestyle=':', linewidth="0.3");
        plt.legend(fontsize = 8,bbox_to_anchor=(1.05, 1.0), loc='upper left') #loc='best')

        # Remove the top and right spines
        sns.despine()
        plt.show()
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise

def get_coverage_scores(Fair,DASP_Labels,Tools):
    coverageScores = pd.DataFrame(columns = ['Tool']+ DASP_Labels)

    if Fair:
        performanceResultFolder = './Results/Evaluations_Fair/TestSet/'
    else:
        performanceResultFolder = './Results/Evaluations/TestSet/'

    for tool in Tools:
        evaluationDF = pd.read_csv(performanceResultFolder+tool+'.csv')
        Labels = evaluationDF['Label']
        newRowIndex = len(coverageScores)

        coverageScores.at[newRowIndex,'Tool'] = tool
        for i in range(0, len(Labels)):
            coverageScores.at[newRowIndex,Labels[i]] = evaluationDF.at[i,'Coverage']

    return coverageScores