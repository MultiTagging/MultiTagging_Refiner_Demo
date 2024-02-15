
import pandas as pd
import os
import json
from pathlib import Path
import numpy as np
#-------------------------------------------
#Get the correct path to the reports main directory
#-------------------------------------------
self_dir = Path(__file__).resolve().parents[1]
#-------------------------------------------
def parse(tool,reportsLocation,reportSource):
    path = self_dir /reportsLocation
    toolTags = pd.DataFrame(columns=['contractAddress', tool+'_Labels'])
    match reportSource:
        case 0:
            match tool:
                case 'Mythril':
                    try:
                        for filename in os.listdir(path):
                            codes = []
                            if os.path.getsize(path/filename) != 0:
                                file = open(path/filename,errors="ignore")
                                data = file.readlines()
                                file.close()
                                for line in data:
                                    if 'SWC ID' in line and line.rstrip() not in codes:
                                        codes.append(line.rstrip())
                            else:
                                codes ='error'
                            toolTags.loc[len(toolTags)]=[filename.rstrip().rsplit('.')[0],codes]
                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")  
                case 'Solhint':
                    try:
                        for filename in os.listdir(path):
                            if '.json' in filename:
                                codes = []
                                if os.path.getsize(path/filename) != 0:
                                    file = open(path/filename,errors="ignore")
                                    data = pd.DataFrame(json.load(file))
                                    file.close()
                                    if 'ruleId' not in data.keys() and data['severity'][0] == 'Error':
                                        codes.append('error')
                                    else:
                                        codes = data['ruleId'].unique()
                                else:
                                    codes.append('error')
                                toolTags.loc[len(toolTags)]=[filename.rstrip().rsplit('.')[0],codes]
                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
                case 'Slither':
                    try:
                        for filename in os.listdir(path):
                            codes = []
                            if os.path.getsize(path/filename) != 0:
                                file = open(path/filename,errors="ignore")
                                data = json.load(file)
                                file.close()
                                for i in range(0,len(data['results']['detectors'])):
                                    codes.append(data['results']['detectors'][i]['check'])
                                codes = list(dict.fromkeys(codes))
                            else:
                                codes ='error'
                            toolTags.loc[len(toolTags)]=[filename.rstrip().rsplit('.')[0],codes]
                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
                case 'VeriSmart':
                    try:
                        for filename in os.listdir(path):
                            codes = []
                            if os.path.getsize(path/filename) != 0:
                                file = open(path/filename,errors="ignore")
                                data = file.readlines()
                                file.close()
                                for line in data:
                                    if '"check"' in line and line.rstrip() not in codes:
                                        codes.append(line.rstrip())
                            else:
                                codes ='error'
                            toolTags.loc[len(toolTags)]=[filename.rstrip().rsplit('.')[0],codes]
                        print(tool + " tags have been extracted successfully")
                        return toolTags
                    except IOError:
                        print("Path not exist")
        case 1:
            try:
                reportsDF = pd.DataFrame()

                for filename in os.listdir(path):
                    if '.csv' in filename:
                        df = pd.read_csv(path/filename)
                        reportsDF = pd.concat([reportsDF, df], ignore_index=True)
                
                reportsDF = reportsDF.drop_duplicates(subset='basename', keep='last')
                reportsDF['basename']=reportsDF['basename'].str.rstrip('.sol')
                reportsDF['findings'] = np.where((reportsDF['findings']== '{}') & (reportsDF['errors'] != '{}'), 'error', reportsDF['findings'])
                
                reportsSubDF = reportsDF[['basename','findings','duration']]
                reportsSubDF['findings'] = reportsSubDF['findings'].str.replace('{','')
                reportsSubDF['findings'] = reportsSubDF['findings'].str.replace('}','')
                reportsSubDF['findings'] = reportsSubDF['findings'].str.rsplit(',')

                reportsSubDF = reportsSubDF.rename(columns={'basename':'contractAddress','findings':tool+'_Labels','duration':tool+'_AnalysisTime'})
                
                print(tool + " tags have been extracted successfully")
                return reportsSubDF
            except IOError:
                print("Path not exist")