# encoding: utf-8 
import sys
import os
import pyshark
from bs4 import BeautifulSoup
import time
import multiprocessing
import sqlite3

def getHtmlFromPcap(pcapFileName,tsharkPara):
    #param = {'-X': 'lua_script:getHttpTitleAndDesc.lua'}
    #param = [ '-X', 'lua_script:getHttpTitleAndDesc.lua','-X', 'lua_script1:pcapFile/temp','-X', 'lua_script1:data-text-lines']
    cap = pyshark.FileCapture(input_file=pcapFileName, custom_parameters=tsharkPara)
    cap.load_packets()
    #for pak in cap:
        #pas

def getAllFileName(filePath,allFileName):
    #for filename in os.listdir(filePath):
        #allFileName.append(filename)
        #print(filename)
    for root,dirs,files in os.walk(filePath):
        allFileName[root] = files
        #for f in files:
            #allFileName.append(os.path.join(root,f))
            #print(os.path.join(root,f).split('/')[-1])
            

    #allFileName.sort()


def createSqlite3Table(createSqlcmd):
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()

    c.execute(createSqlcmd)

    conn.commit()
    conn.close()

def insertDataToSqlite3Table(data,insertSqlcmd):

    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.executemany(insertSqlcmd, data)
    conn.commit()
    conn.close()
    print('sql insert data succ')


def readSqlite3Table(selectSqlcmd):
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute(selectSqlcmd)
    return c.fetchall()
    #print c.fetchall()


def manageMultiProcess(task,rootPath,allFileName):
    manager =  multiprocessing.Manager()
    rowInfo =  manager.list()
    lock = manager.Lock()
    pool = multiprocessing.Pool(processes = 50)
    

    startTime = time.time()

    for aFileName in allFileName:
        #task(aCertFileName)
        pool.apply_async(task, args=(rootPath,aFileName,rowInfo,lock,))

    pool.close()
    pool.join()

    endTime = time.time()

    print("多进程执行耗时：{0:.2f}".format(endTime - startTime))

    return rowInfo
