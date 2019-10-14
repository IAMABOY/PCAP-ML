#!/bin/bash
find /home/zte/data/erde/googleFreeTrans/pcapFile/湖南长沙报文_20190705/pcap_443 -name '*.pcap' > pcapFileName.txt
#find /home/zte/data/erde/googleFreeTrans/unrn/code/pcapDecoder/pcapFile -name '*.pcap' > pcapFileName.txt
#find /home/zte/data/erde/googleFreeTrans/unrn/code/pcapDecoder/pcapFile/ssl '*.pcap' > pcapFileName.txt
while read LINE
do

	 #if [ `grep -icw \$LINE pcapForIpsensorOldFileName.txt` != 0 ]
	 #then
	 	#echo $LINE
	 	#$path = "/home/zte/docker/pcap/getit/"${LINE}".pcap"
	 	#fileName = ${LINE%%/*}
	 	#echo ${LINE##*/}
	 	
	 	folderName=${LINE%.*}
	 	fileName=${LINE##*/}
	 	echo ${folderName}
	 	if [ ! -d $folderName ]; then
		    mkdir -p -m 777 $folderName
		fi

	 	#tshark -X lua_script:getHttpTitleAndDesc.lua -X lua_script1:${folderName} -X lua_script1:data-text-lines -r $LINE -q
	 	tshark -X lua_script:getSslCertInfo.lua -X lua_script1:${folderName} -X lua_script1:ssl.handshake.certificate -r $LINE -q
	 	#echo $path
	 #fi
 done < pcapFileName.txt

 #cat UA.txt | sort -k 2,30 -d| awk '{$1=""}{print $0}' | uniq -c | awk '{$1=""}{print $0}' | grep -v "^$" | rev |sort -d | rev > UASORT.txt
 #cat host.txt | sort -k 2,30 -d| awk '{$1=""}{print $0}' | uniq -c | awk '{$1=""}{print $0}' | grep -v "^$" | rev |sort -d | rev > hostSORT.txt

