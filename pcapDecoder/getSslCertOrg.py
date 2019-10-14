 # encoding: utf-8 
import json
import os
import sys
import json
import sqlite3
from OpenSSL import crypto
import gc 
import time
import multiprocessing
import commFunc

def getCertSubjectInfo(certName):
    
    certSubjectInfo = []
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, open(certName,'rb').read()) 
        subject = cert.get_subject() 
        certSubjectInfo.append(subject.O)
        certSubjectInfo.append(subject.C)
        certSubjectInfo.append(subject.L)
        certSubjectInfo.append(subject.ST)
        certSubjectInfo.append(subject.CN)
        certSubjectInfo.append(subject.OU)
        # 得到证书颁发机构 
        #issuer = cert.get_issuer() 
        #issued_by = issuer.CN
        #if subject.O != None:
            #print(subject.O) 
        san = None
        for index in range(cert.get_extension_count()):                                                                                                                                                         
            ext = cert.get_extension(index)    
            #print(type(ext.get_short_name()))                                                                                                                                                                     
            #print(type(str.encode('subjectAltName')))                                                                                                                                                                   
            if str.encode('subjectAltName') == ext.get_short_name():                                                                                                    
                #print(str(ext))
                san = str(ext)
                break
            else:
                pass
        certSubjectInfo.append(san)
        del cert
        del subject
        del ext
        gc.collect()
    except Exception as e:
        print(certName)
        print(e)
    return certSubjectInfo


def certTask(rootPath,aCertFileName,rowInfo,lock):
    aFileNameInfo = aCertFileName.split('_')

    aFileNameInfo[-1] = aFileNameInfo[-1][0]#只取4.cer中的ipversion部分4
    aCertSubjectInfo = getCertSubjectInfo(rootPath+ str(os.path.sep) +aCertFileName)

    with lock:
        if (len(rowInfo) % 50000 == 0):
            print(len(rowInfo))

        if(14 == len(aFileNameInfo + aCertSubjectInfo)):
            rowInfo.append(aFileNameInfo + aCertSubjectInfo)

    #return aFileNameInfo + aCertSubjectInfo
    #print(rowInfo)

if __name__ == '__main__':

    if len (sys.argv) < 3:
        print('HELP: python {} <PCAP_PATH> <CERT_PATH>'.format(sys.argv[0]))
        sys.exit(0)
        #_EXIT_

    pcapFilePath = sys.argv[1]
    certFilePath = sys.argv[2]

    createSqlcmd = '''CREATE TABLE IF NOT EXISTS SSL_CERT_INFO
       (SNI          TEXT  NOT NULL,
       STREAM        INT,
       SRC_IP        TEXT,
       SRC_PORT      INT,
       DST_IP        TEXT,
       DST_PORT      INT,
       IP_VERSION    INT,
       CERT_O        TEXT,
       CERT_C        TEXT,
       CERT_L        TEXT,
       CERT_ST       TEXT,
       CERT_CN       TEXT,
       CERT_OU       TEXT,
       CERT_SAN      TEXT);'''


    commFunc.createSqlite3Table(createSqlcmd)

    allCertFileName = {}
    commFunc.getAllFileName(certFilePath,allCertFileName)

    
    insertSqlcmd = 'INSERT INTO SSL_CERT_INFO VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'

    for rootPath,allFileNameOfAFolder in allCertFileName.items():
        
        sqlData = commFunc.manageMultiProcess(certTask ,rootPath,allFileNameOfAFolder)

        commFunc.insertDataToSqlite3Table(sqlData,insertSqlcmd)

    selectSqlcmd = 'select * from SSL_CERT_INFO'
    #print(commFunc.readSqlite3Table(selectSqlcmd))
    #getTitleDescKeyWords('pcapFile/temp/www.cctv.com_0_192.168.137.231_59716_23.57.66.65_80_4.html')
