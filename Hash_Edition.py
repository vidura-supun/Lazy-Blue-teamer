import pandas as pd
import os
from datetime import datetime
import shutil
import time
import sys
import re

dirName = "IPS_Old_CSVs_U8821"
CurrDirectory = os.getcwd()
nDir = CurrDirectory + "\\" + dirName
fNew =''
fhNew = "PutHashes_Here.txt"
md5_pattern = re.compile(r'[a-fA-F0-9]{32}')
sha256_pattern = re.compile(r'[a-fA-F0-9]{64}')
SR = re.compile(r'SR#\d+')

def directorySetting():        
    files=[f for f in os.listdir('.') if os.path.isfile(f) and f.endswith('.csv') and f.startswith('hashblock')]
    dirs = [d for d in os.listdir('.') if os.path.isdir(d)]

    if not files:
        createFile()
        CreateHashFile()
        print("Pre-Requisits have been configured, please Re run!!")
        time.sleep(3)
        sys.exit()       
        
    if files:
        if not os.path.isfile(fhNew):
            CreateHashFile()
        copyData(files)
        if not dirs:           
            os.makedirs(nDir)
            for fi in files:
              os.replace(CurrDirectory+"\\"+fi, nDir+"\\"+fi)  
        if dirs:
            for di in dirs:
                if di == dirName:
                    for fi in files:
                        os.replace(CurrDirectory+"\\"+fi, nDir+"\\"+fi) 

def copyData(files):
    global fNew
    tNow = datetime.now()
    tFile = tNow.strftime('%d%m%Y_%H%M')
    fNew = "hashblock_" + tFile + ".csv"
    for f in files:
        shutil.copy(CurrDirectory+"\\"+ f, CurrDirectory+"\\"+ fNew)

def createFile():
    tNow = datetime.now()
    tFile = tNow.strftime('%d%m%Y_%H%M')
    fNew = open("hashblock_" + tFile + ".csv","x", encoding='utf-8')

def CreateHashFile():
    open(fhNew,"x")

def ExtractHashes():
    md5_hashes = []
    sha256_hashes = []
    SRNum = ''
    with open(fhNew, 'r') as file:
        for line in file:
            matches256 = sha256_pattern.findall(line)
            matches5 = md5_pattern.findall(line)
            matchesSR = SR.search(line)
            if matchesSR:
                SRNum = matchesSR.group()
            md5_hashes.extend(matches5)
            sha256_hashes.extend(matches256)
    return md5_hashes, sha256_hashes, SRNum

def AppendHashes(md5, sha256,SR):
    Count_md5 = len(md5)
    if os.stat(fNew).st_size == 0:
        additionalInfo={
            'risk1':'high',
            'risk2' : 'high',
            'cat':'AV',
            'SR' : SR
        }
        
        df_md5= pd.DataFrame({
            'hashID': ['hash'+ str(i) for i in range(0,Count_md5)],
            'hash': md5,
            'type': ['MD5']*len(md5),
            'risk1': [additionalInfo['risk1']]*len(md5),
            'risk2': [additionalInfo['risk2']]*len(md5),
            'cat': [additionalInfo['cat']]*len(md5),
            'SR': [additionalInfo['SR']]*len(md5)
        })

        df_sha256= pd.DataFrame({
            'hashID': ['hash'+ str(i) for i in range(Count_md5,Count_md5+len(sha256))],
            'hash': sha256,
            'type': ['SHA256']*len(sha256),
            'risk1': [additionalInfo['risk1']]*len(sha256),
            'risk2': [additionalInfo['risk2']]*len(sha256),
            'cat': [additionalInfo['cat']]*len(sha256),
            'SR': [additionalInfo['SR']]*len(sha256)
        })
        dfBoth = pd.concat([df_md5,df_sha256], ignore_index=True)
        dfBoth.to_csv(fNew, mode='a', index=False, header=False)

    if os.stat(fNew).st_size > 0:
        df = pd.read_csv(fNew)
        rows = len(df)+2
        additionalInfo={
            'risk1':'high',
            'risk2' : 'high',
            'cat':'AV',
            'SR' : SR
        }

        df_md5= pd.DataFrame({
            'hashID': ['hash'+ str(i) for i in range(rows,rows+len(md5))],
            'hash': md5,
            'type': ['MD5']*len(md5),
            'risk1': [additionalInfo['risk1']]*len(md5),
            'risk2': [additionalInfo['risk2']]*len(md5),
            'cat': [additionalInfo['cat']]*len(md5),
            'SR': [additionalInfo['SR']]*len(md5)
        })

        df_sha256= pd.DataFrame({
            'hashID': ['hash'+ str(i) for i in range(rows+Count_md5,rows+Count_md5+len(sha256))],
            'hash': sha256,
            'type': ['SHA256']*len(sha256),
            'risk1': [additionalInfo['risk1']]*len(sha256),
            'risk2': [additionalInfo['risk2']]*len(sha256),
            'cat': [additionalInfo['cat']]*len(sha256),
            'SR': [additionalInfo['SR']]*len(sha256)
        })
        dfBoth = pd.concat([df_md5,df_sha256], ignore_index=True)
        dfBoth.to_csv(fNew, mode='a', index=False, header=False)        

def debug():
    print("fNew:" + fNew)

def main():
    directorySetting()
    md5, sha256, SR = ExtractHashes()
    AppendHashes(md5, sha256, SR)
    ##debug()
    ##print(md5)
    ##print(sha256)
    ##print(SR)

main()    