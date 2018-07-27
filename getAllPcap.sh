#!/bin/bash
find -name '*.pcap' > pcapFileName.txt
while read LINE
do

	 #if [ `grep -icw \$LINE pcapForIpsensorOldFileName.txt` != 0 ]
	 #then
		#echo $LINE
		#$path = "/home/zte/docker/pcap/getit/"${LINE}".pcap"
		#fileName = $LINE%%/*
		#echo $fileName
		echo ${LINE##*/}
		#tshark -i 3 -w MyCapture.pcap -s 80 -b filesize:1000000
		#tshark -X lua_script:flowcut.lua -X lua_script1:${LINE##*/} -r $LINE  -q -l
		#tshark -X lua_script:getFirstBlock.lua -X lua_script1:${LINE##*/} -r $LINE  -q -l
		tshark -X lua_script:getIntervalBlock.lua -X lua_script1:${LINE##*/} -r $LINE  -q -l
		#echo $path
	 #fi
 done < pcapFileName.txt






 #cat UA.txt | sort -k 2,30 -d| awk '{$1=""}{print $0}' | uniq -c | awk '{$1=""}{print $0}' | grep -v "^$" | rev |sort -d | rev > UASORT.txt
 #cat host.txt | sort -k 2,30 -d| awk '{$1=""}{print $0}' | uniq -c | awk '{$1=""}{print $0}' | grep -v "^$" | rev |sort -d | rev > hostSORT.txt

