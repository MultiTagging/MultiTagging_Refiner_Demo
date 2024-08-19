import pandas as pd

def createPerformanceOutFiles(Tools,Bases):

    avgAnalysisTimeAndFailureRateDF = pd.DataFrame(columns=['Base','Tool','minAnalysisTime','maxAnalysisTime','avgAnalysisTime','FailureRate'])
    index = -1
    for base in Bases:
        for tool in Tools:
            index = index +1
            avgAnalysisTimeAndFailureRateDF.at[index,'Base'] = base
            avgAnalysisTimeAndFailureRateDF.at[index,'Tool'] = tool

    avgAnalysisTimeAndFailureRateDF.to_csv('./Results/Performance/avgAnalysisTimeAndFailureRate.csv',index=False)
    avgAnalysisTimeAndFailureRateDF.to_csv('./Results/Performance/avgAnalysisTimeAndFailureRate_Fair.csv',index=False)