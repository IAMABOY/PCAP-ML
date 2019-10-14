# encoding: utf-8 
import sys
import os
from bs4 import BeautifulSoup
import time
import multiprocessing
import sqlite3
import logbook
import logbook.more

import config

def getAllFileName(filePath,allFileName):
    #for filename in os.listdir(filePath):
        #allFileName.append(filename)
        #logger.info(filename)
    for root,dirs,files in os.walk(filePath):
        allFileName[root] = files
        #for f in files:
            #allFileName.append(os.path.join(root,f))
            #logger.info(os.path.join(root,f).split('/')[-1])
            

    #allFileName.sort()


def createSqlite3Table(createSqlcmd):
    conn = sqlite3.connect('pcapInfo.db')
    c = conn.cursor()

    c.execute(createSqlcmd)

    conn.commit()
    conn.close()

def insertDataToSqlite3Table(data,insertSqlcmd):

    conn = sqlite3.connect('pcapInfo.db')
    c = conn.cursor()
    c.executemany(insertSqlcmd, data)
    conn.commit()
    conn.close()
    logger.info('sql insert data succ')


def readSqlite3Table(selectSqlcmd):
    conn = sqlite3.connect('pcapInfo.db')
    c = conn.cursor()
    c.execute(selectSqlcmd)
    return c.fetchall()
    #logger.info c.fetchall()


def logFormate(record,handler):
    formate = "[{date}] [{level}] [{filename}] [{func_name}] [{lineno}] {msg}".format(
        date = record.time,                              # 日志时间
        level = record.level_name,                       # 日志等级
        filename = os.path.split(record.filename)[-1],   # 文件名
        func_name = record.func_name,                    # 函数名
        lineno = record.lineno,                          # 行号
        msg = record.message                             # 日志内容
    )
    return formate


def initLogger(filename,fileLogFlag=True,stdOutFlag=False):
    LOG_DIR = os.path.join('log')
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    logbook.set_datetime_format('local')

    logger = logbook.Logger(filename)
    logger.handlers = []

    if fileLogFlag:
        logFile = logbook.TimedRotatingFileHandler(os.path.join(LOG_DIR, '%s.log' % 'log'),date_format='%Y-%m-%d', bubble=True, encoding='utf-8')
        logFile.formatter = logFormate
        logger.handlers.append(logFile)

    if stdOutFlag:
        logStd = logbook.more.ColorizedStderrHandler(bubble=True)
        logStd.formatter = logFormate
        logger.handlers.append(logStd)

    return logger



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

    logger.info("多进程执行耗时：{0:.2f}".format(endTime - startTime))

    return rowInfo
