#-*- coding:utf8 -*-
#import matplotlib
#matplotlib.use('Agg')

import matplotlib.pyplot as plt

import csv
import os
from sklearn import preprocessing
from sklearn import tree
from sklearn.model_selection import train_test_split
import pickle


def storeTree(inputTree, filename):

    #序列化决策树,存入文件
    fw = open(filename,'wb')
    pickle.dump(inputTree,fw)
    fw.close()
 
def grabTree(filename):

    #将文件转换为决策树到内存 
    fr = open(filename,'rb')
    return pickle.load(fr)



dataPath = 'all_ios_traindata_newFeature_20180726_100K.csv'#训练数据
testPath = 'all_ios_testdata_newFeature_20180726_100K.csv'#测试数据
#print(path)
dataReader = csv.reader(open(dataPath,'r'))
testReader = csv.reader(open(testPath,'r'))

trainData = []
testData = []
trainLabel = []
testLabel = []
trainFilename = []
testFilename = []

#读入训练数据
for row in dataReader:
	#print(row[1])
	#trainData.append([float(item) for item in row])
	trainDataARow = []
	rowLength=len(row)
	if not row[0][0].isdigit():
		continue
	for number,item in enumerate(row):
		if number == (rowLength-2):
			trainLabel.append(int(item))#第八列表示的是类别,需要将字符串转换为整形
		if number < (rowLength-2):
			trainDataARow.append(float(item))#前七列表示的是每一个维度的数据，需要将字符串转换为float
		if number == (rowLength-1):
			trainFilename.append(item)#第九列表示的是文件的名称

	trainData.append(trainDataARow)

#读入测试数据
for row in testReader:
	#print(row[1])
	#testData.append([float(item) for item in row])
	testDataARow = []
	rowLength=len(row)
	if not row[0][0].isdigit():
		continue
	for number,item in enumerate(row):
		if number == (rowLength-2):
			testLabel.append(int(item))#第八列表示的是类别,需要将字符串转换为整形
		if number < (rowLength-2):
			testDataARow.append(float(item))#前七列表示的是每一个维度的数据，需要将字符串转换为float
		if number == (rowLength-1):
			testFilename.append(item)#第九列表示的是文件的名称
			
	testData.append(testDataARow)


#下面是LR算法
print("-------------------")
print("以下是DT算法")

dataScaler = preprocessing.StandardScaler().fit(trainData)
testScaler = preprocessing.StandardScaler().fit(testData)
#data_scaled = preprocessing.scale(trainData)
#test_scaled = preprocessing.scale(testData)

#min_max_scaler =preprocessing.MinMaxScaler()

#print("sss:",min_max_scaler.fit_transform(testData))

#print("训练归一化参数",dataScaler)
#print("训练数据期望:",dataScaler.mean_)
#print("训练数标准差:",dataScaler.scale_)
#print("训练数据归一化结果:",dataScaler.transform(trainData))

#print("测试归一化参数",testScaler)
#print("测试数据期望:",testScaler.mean_)
#print("测试数据标准差:",testScaler.scale_)
#print("测试数据归一化结果:",testScaler.transform(testData))

#print("训练数据期望:",data_scaled.mean(axis=1))
#print("训练数标准差:",data_scaled.std(axis=1))
#print("测试数据期望:",test_scaled.mean(axis=1))
#print("测试数据标准差:",test_scaled.std(axis=1))


#classWeight ={1:0.1,2:0.1,3:0.15,4:0.15,5:0.2,6:0.3}
#classWeight ={1:0.03125,2:0.03125,3:0.0625,4:0.125,5:0.25,6:0.5}
classWeight ={1:0.50151218 ,2:0.10939394,3:0.06222222,4:0.32687166,5:0}

    
classifier = tree.DecisionTreeClassifier(splitter='best',presort=True,class_weight='balanced')
#trainLabel = [1,1,1,2,2,2,3,3,3,4,4,4,4,5,5,5,6,6,6,6]

#trainData = dataScaler.transform(trainData)

#testData = testScaler.transform(testData)

#print(testData)

#classifier.fit(trainData,trainLabel)
classifier.fit(dataScaler.transform(trainData),trainLabel)
#classifier.fit(min_max_scaler.fit_transform(trainData),trainLabel)
#classifier.fit(data_scaled,trainLabel)

storeTree(classifier,"decisionTree.dot")

classifier=grabTree("decisionTree_sixFeature_100K.dot")

#print("决策树预测概率:",classifier.predict_proba(testData))
#print(classifier.decision_path(testData))


#print("决策树预测结果:",classifier.predict(testData))
#print(classifier.feature_importances_)
#print(classifier.score(testData,testLabel))
#predictResult = classifier.predict(testData)


print("决策树预测结果:",classifier.predict(testScaler.transform(testData)))
print(classifier.feature_importances_)
print(classifier.score(testScaler.transform(testData),testLabel))
predictResult = classifier.predict(testScaler.transform(testData))


count = 0
while count < len(testLabel):
	if(predictResult[count] != testLabel[count]):
		print(predictResult[count],testLabel[count],testFilename[count])
	count = count + 1



#print("LR预测结果:",classifier.predict_proba(testData))

#print("LR预测结果:",classifier.predict(testScaler.transform(testData)))
#print("LR预测结果:",classifier.predict_proba(testScaler.transform(testData)))

#print("LR预测结果:",classifier.predict(min_max_scaler.fit_transform(testData)))


#print("LR预测结果:",classifier.predict_proba(min_max_scaler.fit_transform(testData)))

#print("LR预测结果:",classifier.predict(test_scaled))
#print("LR预测结果:",classifier.predict_proba(test_scaled))