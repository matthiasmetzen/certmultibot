from copy import deepcopy
import yaml
import os
import glob
from termcolor import colored

def loadYamlFile(filepath):
    if not os.path.exists(filepath):
        raise Exception("file {} does not exist". format(filepath))
    if not os.path.isfile(filepath):
        raise Exception("cannot read {}: not a file".format(filepath))
    with open(filepath, "r") as f:
        return yaml.load(f, Loader=yaml.FullLoader)
    
def getYamlFilesInDir(path):
    if not (os.path.exists(path) or os.path.isdir(path)):
        raise Exception('Could not find {} or not a  directory'.format(path))
    npath = os.path.normpath(path)
    return glob.glob(path + '/*.yml') + glob.glob(path + '/*.yaml')

def getDomainsFromDir(path):
    res = {}
    files = getYamlFilesInDir(path)
    
    if not files:
        print(colored(f"WARNING: no files found in {path}", "red"))
        
    for f in files:
        content = loadYamlFile(f)
        if content.get('disabled', False):
            continue
        domains = content.get('domains', {})
        if not type(content['domains']) == dict:
            raise Exception("Error reading {}: 'domains' is not a map".format(f))
        
        for k in domains.keys():
            if k in res:
                raise Exception("Found multiple definitions for {}".format(k))
            item = domains.get(k, {})
            if not item:
                item = {}
            
            if item.get('disable-https', False):
                continue
                
            subdomains = item.get('subdomains', {})

            v_clean = deepcopy(item)
            if not type(subdomains) == dict:
                raise Exception("Error reading {}: 'domains.{}.subdomains' is not a map".format(f, k))
            for sk in subdomains.keys():
                if type(subdomains[sk]) == dict and subdomains[sk].get('disable-https', False):
                    del v_clean['subdomains'][sk]
            
                            
            if item.get('subdomains-only', False):
                for sk in v_clean.get('subdomains', {}).keys():
                    res[f"{sk}.{k}"] = {}
                continue
                
            res[k] = v_clean
    return res