from Scripts.tagger import generateTags
from Scripts.evaluator import eval
from Scripts.plotting import plot_result
from Scripts.toolOverlap import getOverlap
from Scripts.election import electLabel
from Scripts.toolOverlap_perVuln import getOverlapPerV
from Scripts.ToolEfficiency import get_toolEfficiency
from Scripts.createPerformanceOutFiles import createPerformanceOutFiles

import os
from pathlib import Path
import json

import pandas as pd

import warnings as w
w.simplefilter(action='ignore',category=FutureWarning)

Tools = ['MAIAN','Mythril','Semgrep','Slither','Solhint','VeriSmart']
#-------------------------------------------
#Get the correct path to the configuration file
#-------------------------------------------
config_file_name = 'Scripts/config.json'
self_dir = Path(__file__).resolve().parent
config_file_path = self_dir / config_file_name
#-------------------------------------------
configFile = open(config_file_path)
config_File = json.load(configFile)
configFile.close()

def main():
    
    print("MultiTagging Framework")

    flag = True
    while flag:
        print('.'*50 + '\n')
        print('Enter the number of the selected function:\n 1: Get the labeled data for the tool reports.\n 2: Get vote-based labeled data. \n 3: Get the evaluation report.\n 4: Get the evaluation chart.\n 5: Get tools overlap degree.\n 6: Exit')
        print('.'*50 + '\n')
        option = int(input('Your choice: '))

        match option:
            case 1:
                try:
                    tool = input("Enter the tool name: ")
                    tool = validation(tool,'tool')
                    if tool is False :
                        print('Wrong input or MultiTagging does not support this tool')
                    else:
                        source = int(input("Enter 1 if you used SmartBugs to run the tool, otherwise enter 0: "))
                        if source not in [0,1]:
                            print('Wrong input; The source must be either 0 or 1')
                        else:
                            labeledDS =generateTags(tool,source)
                            print(labeledDS)  
                except:
                    print('Unexpected error')
            case 2:
                try:
                    toolList = getToolsList()
                    if len(toolList) >1 or 'All' in toolList:
                        baseFlieName = input("Enter the base data file name, e.g., SBcurated: ")
                        baseFlieName = validation(baseFlieName,'BaseDataFile')
                        if baseFlieName is False:
                            print('Wrong input, The base data file does not found')
                        else:
                            Fair = input()
                            if Fair not in [True, False]:
                                print('Wrong Input')
                            else:
                                #tools performance + overlap..
                                print('The data is being processed now, wait a moment...\n\n')
                                voteBasedLabeledData = electLabel(baseFlieName,toolList,Fair)
                                print('Vote Based-Labeled Data: \n', voteBasedLabeledData,'\n')
                    else:
                        print('You must pass at least two tool names')
                except:
                    print('Unexpected error')  
            case 3:
                try:
                    dataFileName = input("Enter the labeled data file name (it is the same as the tool name), e.g., Slither: ")
                    dataFileName = validation(dataFileName,'tool')
                    if dataFileName is False :
                        print('Wrong input, The labeled data file does not found')
                    else: 
                        baseFlieName = input("Enter the base data file name, e.g., SBcurated.csv: ")
                        baseFlieName = validation(baseFlieName,'BaseDataFile')
                        if baseFlieName is False:
                            print('Wrong input, The base data file does not found')
                        else:
                            print(baseFlieName)
                            print(dataFileName)

                            #create avgAnalysisTimeAndFailureRate files if not exit
                            files = os.listdir('./Results/Performance/')
                            if not 'avgAnalysisTimeAndFailureRate.csv' in files or not 'avgAnalysisTimeAndFailureRate_Fair.csv' in files:
                                Bases = baseFlieName.split('.')[0]
                                createPerformanceOutFiles(Tools,Bases)

                            evaluationResult = eval(dataFileName,baseFlieName+'.csv')
                            print('The evaluation result of',dataFileName,'using the base',baseFlieName,'is',evaluationResult)
                except:
                    print('Unexpected error')
            case 4:
                try:
                    toolList = getToolsList()
                    if len(toolList) > 0 :
                        baseList = getBasesList()
                        if len(baseList) > 0:
                            Eval_Results = plot_result(toolList,baseList)
                            #Eval_Results.to_csv('./Results/Charts/AllResult.csv',index=False)
                            print('Evaluation Data:\n',Eval_Results)
                        else:
                            print('Wrong input')
                    else:
                            print('Wrong input')   
                except:
                    print('Unexpected error')
            case 5:
                try:
                    toolList = getToolsList()
                    if len(toolList) >1 or 'All' in toolList:
                        print('The data is being processed now, wait a moment...\n\n')
                        overlapDF = getOverlap(toolList)
                        print('Tools Overlap Degrees: \n', overlapDF,'\n')
                    else:
                        print('You must pass at least two tool names')
                except:
                    print('Unexpected error')
            case 6:
                flag =False

def validation(input,type):
    match type:
        case 'tool':
            ToolsLower = list(pd.Series(Tools).str.lower())
            if input.lower() in ToolsLower:
                #print(Tools[ToolsLower.index(input)])
                return Tools[ToolsLower.index(input)]
            else:
                return False
        case 'LabeledDataFile' | 'BaseDataFile':
            if '.' in input:
                input = input.split('.')[0]
            
            match type:
                case 'LabeledDataFile':
                    LabeledData_Dir = config_File['LabeledData'][0]['Path']
                case 'BaseDataFile':
                    LabeledData_Dir = config_File['BaseDS'][0]['Path']

            dataFiles = [f.name.split('.')[0] for f in os.scandir(LabeledData_Dir) if f.is_file() and '.csv' in f.name]
            if input not in dataFiles:
                return False
            else:
                return input

def getToolsList():
    Tools =[]
    AllTools = int(input("Enter 1 if you want to pass all tools, otherwise enter 0 to pass the tool names one by one: "))
    if AllTools not in [0,1]:
        print('Wrong input')
    elif AllTools == 1:
        Tools.append('All')
    else:
        print('Enter the name of the tool and press Enter (to Exit, press Enter directly): ')
        while True:  
            tool = input()  
            if len(tool) == 0:  
                break
            tool = validation(tool,'tool')
            if tool is False :
                print('Wrong input or MultiTagging does not support this tool')
            else:
                Tools.append(tool)
            print('Enter the name of the next tool and press Enter (to Exit, press Enter directly): ')
    return Tools

def getBasesList():
    Bases =[]
    AllBases = int(input("Enter 1 if you want to pass all bases, otherwise enter 0 to pass the base names one by one: "))
    if AllBases not in [0,1]:
        print('Wrong input')
    elif AllBases == 1:
        Bases.append('All')
    else:
        print('Enter the name of the base data and press Enter (to Exit, press Enter directly): ')
        while True:  
            base = input()  
            if len(base) == 0:  
                break
            base = validation(base,'LabeledDataFile')
            if base is False :
                print('Wrong input, Base file does not found')
            else:
                Bases.append(base)
            print('Enter the name of the next base data and press Enter (to Exit, press Enter directly): ')
    return Bases 
main()
