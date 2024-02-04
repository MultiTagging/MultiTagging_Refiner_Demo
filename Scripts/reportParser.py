
import pandas as pd
import os
import json
from pathlib import Path
#-------------------------------------------
#Get the correct path to the reports main directory
#-------------------------------------------
self_dir = Path(__file__).resolve().parents[1]
print(self_dir)
#-------------------------------------------
def parse(tool,reportsLocation):
    path = self_dir /reportsLocation
    print(path)
    toolTags = pd.DataFrame(columns=['contractAddress', tool+'_labels'])
    
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
                    codes = []
                    if os.path.getsize(path/filename) != 0:
                        file = open(path/filename,errors="ignore")
                        data = json.load(file)
                        return(data)
                        '''data = file.readlines()
                        file.close()
                        for line in data:
                            if 'SWC ID' in line and line.rstrip() not in codes:
                                codes.append(line.rstrip())'''
                    else:
                        codes ='error'
                    '''toolTags.loc[len(toolTags)]=[filename.rstrip().rsplit('.')[0],codes]
                print(tool + " tags have been extracted successfully")
                return toolTags'''
                return data
            except IOError:
                print("Path not exist") 