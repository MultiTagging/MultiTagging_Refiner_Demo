from reportParser import parse
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

def generateTags(tool):
    Tools =['MAIAN','Mythril','Semgrep','Slither','Solhint','VeriSmart']
    configFile = open(config_file_path)
    reportsLocation = json.load(configFile)
    configFile.close()
    
    vulnReportsPath = reportsLocation['Reports_Directory_Path'][Tools.index(tool)]['Path']
    labeledSC = parse(tool,vulnReportsPath)
    
    analysisTimeReportsPath = reportsLocation['AnalysisTime_Directory_Path'][Tools.index(tool)]['Path']    
    tool_LabeledDS = pd.DataFrame(get_ToolAnalysisTime(tool, analysisTimeReportsPath))

    labeledSC= labeledSC.merge(tool_LabeledDS,on='contractAddress')
    return labeledSC

def get_ToolAnalysisTime(tool, analysisTimeReportsPath):
    self_dir = Path(__file__).resolve().parents[1]
    path = self_dir / analysisTimeReportsPath
    analsisTime = []
    try:
        for filename in os.listdir(path):
            if os.path.getsize(path/filename) != 0:
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
        return analsisTimeDF
    except IOError:
        print("Path not exist") 

#print(generateTags('Mythril'))