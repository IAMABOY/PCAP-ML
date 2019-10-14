 #!/bin/bash

find ../../../pcapFile/2019/pcap_80 -name '*.pcap' > pcapFileName.txt

while read LINE
do
	 	folderName=${LINE%.*}
	 	fileName=${LINE##*/}
	 	echo ${folderName}
	 	if [ ! -d $folderName ]; then
		    mkdir -p -m 777 $folderName
		fi

	 	tshark -X lua_script:getSslCertInfo.lua -X lua_script1:${folderName} -X lua_script1:ssl.handshake.certificate -r $LINE -q
	 	
 done < pcapFileName.txt

 #cat UA.txt | sort -k 2,30 -d| awk '{$1=""}{print $0}' | uniq -c | awk '{$1=""}{print $0}' | grep -v "^$" | rev |sort -d | rev > UASORT.txt
 #cat host.txt | sort -k 2,30 -d| awk '{$1=""}{print $0}' | uniq -c | awk '{$1=""}{print $0}' | grep -v "^$" | rev |sort -d | rev > hostSORT.txt

