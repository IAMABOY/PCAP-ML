#-*- coding:utf8 -*-
#import matplotlib
#matplotlib.use('Agg')

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from scipy.stats import skew
from scipy.stats import kurtosis
import csv

allFileName = []

for filename in os.listdir(r'youtube_ios/iosTestPcapFile/iosTestCsvFile'):
    allFileName.append(filename)

#由于排序是按照字符串顺序的，因此需要将1080改为81080方便后续操作
allFileName.sort()

category = [0]*6
fileNumber = 0
threshold= 100000
out = pd.DataFrame([], columns = ['mean', 'skew','ratio2','var_coef','kurtosis','series','label','file'])

for filename in allFileName:
    
    
    classLabel=0
    #youtube_ios/iosTrainPcapFile/iosTrainCsvFile
    #youtube_ios/iosTestPcapFile/iosTestCsvFile
    dataPath = 'youtube_ios/iosTestPcapFile/iosTestCsvFile/' + filename
    dataReader = csv.reader(open(dataPath,'r'))
    trainDataARow = []
    for row in dataReader:
        
        if row[1] != "aBlockSize":
            if int(row[1]) > threshold:
                trainDataARow.append(int(row[1]))
                #trainData.append(trainDataARow)
    #print trainDataARow

    if filename.find('144P_') != -1:
        classLabel=1
        #continue#144P可能没有高于200000的，不与考虑
    elif filename.find('240P_') != -1:
        classLabel=2
    elif filename.find('360P_') != -1:
        classLabel=3
    elif filename.find('480P_') != -1:
        classLabel=4
    elif filename.find('720P_') != -1:
        classLabel=5
    elif filename.find('81080P_') != -1:
        classLabel=6
    else:
        print("erro")

    #if filename.find('WEBM_xEdT9z_ff0g') != -1:
        #temp11=trainDataARow

    
    

    tem = np.array(trainDataARow)
    #print trainDataARow
    out.at[fileNumber,'mean'] = np.mean(tem)
    out.at[fileNumber,'skew'] = skew(tem)
    q25 = np.percentile(tem, 25)
    q50 = np.percentile(tem, 50)
    q75 = np.percentile(tem, 75)
    out.at[fileNumber,'ratio2'] = 0 if q50-q25==0 else 1.0*(q75-q50)/(q50-q25)
    out.at[fileNumber,'var_coef'] = np.std(tem)/np.mean(tem) if np.mean(tem) != 0 else -1
    out.at[fileNumber,'kurtosis'] = kurtosis(tem)
    seri = np.array([4 if item>=q75 else 3 if item>=q50 else 2 if item>=q25 else 1 for item in tem])
    out.at[fileNumber,'series'] = sum(seri)*1.0/(len(tem))
    print len(tem)
    out.at[fileNumber,'label'] =  classLabel
    out.at[fileNumber,'file'] = filename
    fileNumber = fileNumber + 1
    

#print out
out.to_csv("all_ios_testdata_newFeature_20180726.csv", index=False, sep=',')


#plt.hist(temp11,100,normed=True,facecolor='b',alpha=0.7)
#plt.grid(True)
#plt.show()