from Scripts.reportParser import parse
from Scripts.mapper import map
#from reportParser import parse
#from mapper import map
import json
from pathlib import Path
import os
import pandas as pd
#-------------------------------------------
#Get the correct path to the configuration file
#-------------------------------------------
config_file_name = 'config.json'
self_dir = Path(__file__).resolve().parent
config_file_path = self_dir / config_file_name
#-------------------------------------------

def generateTags(tool,reportSource):
    try:
        Tools =['MAIAN','Mythril','Semgrep','Slither','Solhint','VeriSmart']
        configFile = open(config_file_path)
        config_File = json.load(configFile)
        configFile.close()
        
        vulnReportsPath = config_File['Reports_Directory_Path'][Tools.index(tool)]['Path']
        labeledSC = parse(tool,vulnReportsPath,reportSource)

        if reportSource ==0 and tool != 'VeriSmart':
            analysisTimeReportsPath = config_File['AnalysisTime_Directory_Path'][Tools.index(tool)]['Path']    
            tool_LabeledDS = pd.DataFrame(get_ToolAnalysisTime(tool, analysisTimeReportsPath))
            labeledSC= labeledSC.merge(tool_LabeledDS,on='contractAddress')
        
        VulnerablityMapFilePath = config_File['VulnerablityMap_File_Path'][0]['Path']  
        mapLabeledSC = map(labeledSC,VulnerablityMapFilePath,tool)

        mapLabeledSC.to_csv('./Results/LabeledData/'+tool+'.csv',index=False)
        return mapLabeledSC
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
def get_ToolAnalysisTime(tool, analysisTimeReportsPath):
    self_dir = Path(__file__).resolve().parents[1]
    path = self_dir / analysisTimeReportsPath
    analsisTime = []
    try:
        for filename in os.listdir(path):
            if os.path.getsize(path/filename) != 0 and '.txt' in filename:
                file = open(path/filename,errors="ignore")
                data = file.readlines()
                file.close()
                for line in data:
                    lineToList = line.rstrip().split(" ")
                    analsisTime.append(lineToList)
            
        if len(analsisTime)>0:
            analsisTimeDF = pd.DataFrame(data= analsisTime, columns = ['contractAddress', tool+'_AnalysisTime'])
            analsisTimeDF = analsisTimeDF.drop_duplicates(subset='contractAddress', keep='last')

            analsisTimeDF['contractAddress'].str.strip()
            #print('The AVG analysis time is: ', analsisTimeDF[tool+'_AnalysisTime'].mean())
        return analsisTimeDF
    except IOError:
        print("Path not exist") 

#print(generateTags('Mythril',0))