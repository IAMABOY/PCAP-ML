import csv
import os


allFileName = []

for filename in os.listdir(r'youtube_ios/iosTrainPcapFile/iosTrainCsvFile'):
	allFileName.append(filename)

#sorted(allFileName)

allFileName.sort()

outputFile = open("all_ios_traindata_new20180723.csv",'w')

for filename in allFileName:

	category = [0]*7

	totalBlockNum = 0
	
	path = 'youtube_ios/iosTrainPcapFile/iosTrainCsvFile/' + filename
	#print(path)
	reader = csv.reader(open(path,'rb'))

	

	for row in reader:
		#print row[1]

		if row[1] == 'aBlockSize':
			continue

		if int(row[1]) < 1:
			continue

		if int(row[1]) < 110000:
			category[0] = category[0] + 1
			continue

		if int(row[1]) < 185000:
			category[1] = category[1] + 1
			continue

		if int(row[1]) < 348000:
			category[2] = category[2] + 1
			continue

		if int(row[1]) < 669000:
			category[3] = category[3] + 1
			continue

		if int(row[1]) < 1121000:
			category[4] = category[4] + 1
			continue

		if int(row[1]) < 2171000:
			category[5] = category[5] + 1
			continue

		if int(row[1]) < 10000000:
			category[6] = category[6] + 1
			continue

	totalBlockNum = float(category[0]+category[1]+category[2]+category[3]+category[4]+category[5]+category[6])

	#print(filename,totalBlockNum,category[0],category[1],category[2],category[3],category[4],category[5])
	#print filename,',',round(category[0]/totalBlockNum,4),',',round(category[1]/totalBlockNum,4),',',round(category[2]/totalBlockNum,4),',',round(category[3]/totalBlockNum,4),',',round(category[4]/totalBlockNum,4),',',round(category[5]/totalBlockNum,4)
	#print round(category[0]/totalBlockNum,4),',',round(category[1]/totalBlockNum,4),',',round(category[2]/totalBlockNum,4),',',round(category[3]/totalBlockNum,4),',',round(category[4]/totalBlockNum,4),',',round(category[5]/totalBlockNum,4),',',filename
	if filename.find('144P_') != -1:
		classLabel = 1
	elif filename.find('240P_') != -1:
		classLabel = 2
	elif filename.find('360P_') != -1:
		classLabel = 3
	elif filename.find('480P_') != -1:
		classLabel = 4
	elif filename.find('720P_') != -1:
		classLabel = 5
	elif filename.find('81080P_') != -1:
		classLabel = 6
	else:
		classLabel = 100


	print round(category[0]/totalBlockNum,4),round(category[1]/totalBlockNum,4),round(category[2]/totalBlockNum,4),round(category[3]/totalBlockNum,4),round(category[4]/totalBlockNum,4),round(category[5]/totalBlockNum,4),round(category[6]/totalBlockNum,4),filename,classLabel
	outArray = [round(category[0]/totalBlockNum,4),round(category[1]/totalBlockNum,4),round(category[2]/totalBlockNum,4),round(category[3]/totalBlockNum,4),round(category[4]/totalBlockNum,4),round(category[5]/totalBlockNum,4),round(category[6]/totalBlockNum,4),classLabel,filename]
	
	outputFileWriter = csv.writer(outputFile)
	outputFileWriter.writerow(outArray)
#reader = csv.reader(open(''))   