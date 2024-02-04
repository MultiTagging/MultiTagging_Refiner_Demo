from reportParser import parse
import json
from pathlib import Path
#-------------------------------------------
#Get the correct path to the configuration file
#-------------------------------------------
config_file_name = 'config.json'
self_dir = Path(__file__).resolve().parent
config_file_path = self_dir / config_file_name
#-------------------------------------------

def generateTags(tool):
    print(tool)
    Tools =['MAIAN','Mythril','Semgrep','Slither','Solhint','VeriSmart']
    configFile = open(config_file_path)
    reportsLocation = json.load(configFile)
    configFile.close()
    #print(reportsLocation)
    path = reportsLocation['Reports_Directory_Path'][Tools.index(tool)]['Path']
    #print(reportsLocation['Reports_Directory_Path'][Tools.index(tool)]['Path'])

    return(parse(tool,path))