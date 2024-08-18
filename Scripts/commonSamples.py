import pandas as pd
import json
from pathlib import Path

#Get the correct path to the configuration file
#-------------------------------------------
config_file_name = 'config.json'
self_dir = Path(__file__).resolve().parent
config_file_path = self_dir / config_file_name
#-------------------------------------------

def get_commonSamples(Tools):
    commonAdrrDF = pd.DataFrame(columns=['contractAddress'])

    try:
        '''configFile = open(config_file_path)
        config_File = json.load(configFile)
        configFile.close()'''

        for tool in Tools:
            #Get data labeled by tool
            ToolDS = pd.read_csv('./Results/LabeledData/'+tool+'.csv')

            #Remove errors
            ToolDS = ToolDS[ToolDS[tool+'_Labels'] != "['error']"]
            #print(tool,':',len(ToolDS))
            if len(commonAdrrDF) == 0:
                commonAdrrDF['contractAddress'] = ToolDS['contractAddress'].to_list()
            else:
                commonAdrrDF = commonAdrrDF.merge(ToolDS['contractAddress'], on = 'contractAddress', how = 'inner')
        
        commonAdrr = commonAdrrDF['contractAddress']

        return commonAdrr
    
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise