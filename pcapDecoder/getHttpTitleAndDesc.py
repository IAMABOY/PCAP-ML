# encoding: utf-8 
import sys
import os
from bs4 import BeautifulSoup
import commFunc
import os

def getTitleDescKeyWords(fileName):
    htmlFileContent = open(fileName).read()
    # “<title></title>”
    soup = BeautifulSoup(htmlFileContent, 'lxml')
    title = None

    description = None
    keywords = None

    if soup:
        title = soup.title.get_text()

        # “<meta name="description" content="">”
        soupDesc = soup.find(name='meta', attrs={"name":"description"})
        if soupDesc:
            description = soupDesc.get('content','')

        # “<meta name="keywords" content="">”
        soupKey = soup.find(name='meta', attrs={"name":"keywords"})
        if soupKey:
            keywords = soupKey.get('content','')  

    return [title,description,keywords]


def htmlTask(rootPath,aHtmlFileName,rowInfo,lock):
    aFileNameInfo = aHtmlFileName.split('_')

    aFileNameInfo[-1] = aFileNameInfo[-1][0]#只取4.cer中的ipversion部分4
    aHtmlFileInfo = getTitleDescKeyWords(rootPath+ str(os.path.sep) +aHtmlFileName)

    with lock:
        if (len(rowInfo) % 50000 == 0):
            print(len(rowInfo))

        if(10 == len(aFileNameInfo + aHtmlFileInfo)):
            rowInfo.append(aFileNameInfo + aHtmlFileInfo)

    #return aFileNameInfo + aCertSubjectInfo
    #print(rowInfo)

def gertHtmlFileFromPcap(pcapFilePath,htmlFilePath):
    allPcapFileName = {}
    commFunc.getAllFileName(pcapFilePath,allPcapFileName)

    for rootPath,aPcapFileNameOfAFolder in allPcapFileName.items():
        for aPcapFileName in aPcapFileNameOfAFolder:
            
            aHtmlFileFolder = aPcapFileNameOfAFolder.split('/')[-1]

            aHtmlFileDir = htmlFilePath + str(os.path.sep) + aHtmlFileFolder
            
            if not os.path.exists(aHtmlFileDir):
                os.makedirs(aHtmlFileDir)
            param = [ '-X', 'lua_script:getHttpTitleAndDesc.lua','-X', 'lua_script1:'+aHtmlFileDir,'-X', 'lua_script1:data-text-lines']

            commFunc.getHtmlFromPcap(aPcapFileName,param)


if __name__ == '__main__':

    if len (sys.argv) < 3:
        print('HELP: python {} <PCAP_PATH> <HTML_PATH>'.format(sys.argv[0]))
        sys.exit(0)
        #_EXIT_

    pcapFilePath = sys.argv[1]
    htmlFilePath = sys.argv[2]
    #该方法值型性能远远低于单独值型shell脚本，待研究
    #gertHtmlFileFromPcap(pcapFilePath,htmlFilePath)

    createSqlcmd = '''CREATE TABLE IF NOT EXISTS HTTP_HTML_INFO
       (HOST           TEXT  NOT NULL,
       STREAM          INT,
       SRC_IP          TEXT,
       SRC_PORT        INT,
       DST_IP          TEXT,
       DST_PORT        INT,
       IP_VERSION      INT,
       HTML_TITLE      TEXT,
       HTML_DESC       TEXT,
       HTML_KEYWORDS   TEXT);'''

    commFunc.createSqlite3Table(createSqlcmd)

    allHtmlFileName = {}
    commFunc.getAllFileName(htmlFilePath,allHtmlFileName)

    insertSqlcmd = 'INSERT INTO HTTP_HTML_INFO VALUES (?,?,?,?,?,?,?,?,?,?)'

    for rootPath,allFileNameOfAFolder in allHtmlFileName.items():
        
        sqlData = commFunc.manageMultiProcess(htmlTask,rootPath,allFileNameOfAFolder)

        commFunc.insertDataToSqlite3Table(sqlData,insertSqlcmd)

    selectSqlcmd = 'select * from HTTP_HTML_INFO'
    #print(commFunc.readSqlite3Table(selectSqlcmd))