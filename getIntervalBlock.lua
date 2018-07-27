local args = { ... }--命令行参数列表
local fileName = {}--过滤器对象列表
-- 没有参数返回
if #args == 0 then
    return
end

for i, arg in ipairs(args) do--取tshark传进来的参数
    fileName[i] = arg
    pcapFileName = tostring(fileName[i])
end


local getTcpStream = Field.new("tcp.stream") 
local getUdpStream = Field.new("udp.stream") 

local tcpStreamTable = {}--tcp流的一列,tcp每一条流的索引哈希表  
local udpStreamTable = {}--udp流的一列,udp每一条流的索引哈希表

local tcpStreamSizeForATimeTable = {}--一条tcp流一段时间内的流量
local udpStreamSizeForATimeTable = {}--一条udp流一段时间内的流量

local dataSize = 0  --数据部分流量总和

local tcpStreamRow = {}  --tcp流的一列
local udpStreamRow = {}  --udp流的一列


local getSrcIP = Field.new("ip.src")
local getDstIP = Field.new("ip.dst")


local getTcpSrcPort = Field.new("tcp.srcport")
local getTcpDstPort = Field.new("tcp.dstport")

local getUdpSrcPort = Field.new("udp.srcport")
local getUdpDstPort = Field.new("udp.dstport")


local getTcpLen = Field.new("tcp.len")
local getUdpLen = Field.new("udp.length")

local tcpUserIP = {} --用户IP，用以表示上行数据,后期 pinfo.hi考虑实现
local tcpServerIP = {} --服务器IP，用以表示下行数据,后期 pinfo.lo考虑实现

local udpUserIP = {} --用户IP，用以表示上行数据,后期 pinfo.hi考虑实现
local udpServerIP = {} --服务器IP，用以表示下行数据,后期 pinfo.lo考虑实现

local getFrameProtocol = Field.new("frame.protocols") 


do  
    local function packet_listener()  
        local tap = Listener.new("frame", "tcp || udp")  
        --frame是监听器的名称，tcp是wireshark过滤器规则  
               
        function tap.reset()  
            --print("tap reset")  
        end  
               
        function tap.packet(pinfo,tvb)  
            --回调函数，每收到一个包执行一次。  
            local tcpStream = getTcpStream()  
            local udpStream = getUdpStream()  

            local tcpStreamNumber =tonumber(tostring(tcpStream))  
            local udpStreamNumber =tonumber(tostring(udpStream))  

            local tcpLen = getTcpLen()  
            local udpLen = getUdpLen()  

            local tcpLenNumber =tonumber(tostring(tcpLen))  
            local udpLenNumber =tonumber(tostring(udpLen)) 

            local srcIP = getSrcIP()  
            local dstIP = getDstIP()

            local srcIPString = tostring(srcIP) 
            local dstIPString = tostring(dstIP)

            local srcTcpPort = getTcpSrcPort()  
            local dstTcpPort = getTcpDstPort() 


            local srcTcpPortString = tostring(srcTcpPort) 
            local dstTcpPortString = tostring(dstTcpPort)

            local srcUdpPort = getUdpSrcPort()  
            local dstUdpPort = getUdpDstPort() 


            local srcUdpPortString = tostring(srcUdpPort) 
            local dstUdpPortString = tostring(dstUdpPort)   


            local frameProtocol= getFrameProtocol() 
            local ipProto, transProto, appProto= tostring(frameProtocol):match("(ip)%:(%w+)%:(%w+)")


            --排除ARP等没有流号的报文
            if(udpStream ~= nil)
            then
                udpStreamNumber = udpStreamNumber + 1 --lua下表从1开始,而流号从0开始

                if(udpStreamTable[udpStreamNumber] ~= nil)  --udp处理流程
                then
                    dataSize = dataSize + udpLenNumber -8

                    if(appProto ~= nil)
                    then
                        udpStreamTable[udpStreamNumber][9] = tostring(appProto)
                    end

                    udpStreamTable[udpStreamNumber][10] = udpStreamTable[udpStreamNumber][10]+udpLenNumber -8


                    if(udpUserIP[udpStreamNumber] == srcIPString) --上行数据
                    --if(udpUserIP[udpStreamNumber] == pinfo.hi) --上行数据
                    then
                        udpStreamTable[udpStreamNumber][11]  = udpStreamTable[udpStreamNumber][11]+udpLenNumber -8

                        if(pinfo.rel_ts ~= nil) --终结时间
                        then
                            --print(tonumber(pinfo.number))
                            --print(pinfo.number)
                            udpStreamSizeForATimeTable[udpStreamNumber][pinfo.number]  = {pinfo.rel_ts,udpStreamTable[udpStreamNumber][10],udpStreamTable[udpStreamNumber][11],udpStreamTable[udpStreamNumber][12],udpLenNumber+34,0,pinfo.number}
                            --print(udpStreamTable[udpStreamNumber][10].."  "..udpStreamTable[udpStreamNumber][11].."  "..udpStreamTable[udpStreamNumber][12])
                        end

                    end
                    

                    if(udpServerIP[udpStreamNumber] == srcIPString) --下行数据
                    --if(udpServerIP[udpStreamNumber] == pinfo.hi) --下行数据
                    then

                        udpStreamTable[udpStreamNumber][12] = udpStreamTable[udpStreamNumber][12]+udpLenNumber -8 
                        --print(udpStreamTable[3][12])

                        if(pinfo.rel_ts ~= nil) --终结时间
                        then
                            --print(tonumber(pinfo.number))
                            --print(pinfo.number)
                            udpStreamSizeForATimeTable[udpStreamNumber][pinfo.number]  = {pinfo.rel_ts,udpStreamTable[udpStreamNumber][10],udpStreamTable[udpStreamNumber][11],udpStreamTable[udpStreamNumber][12],udpLenNumber+34,1,pinfo.number}
                            --print(udpStreamTable[udpStreamNumber][10].."  "..udpStreamTable[udpStreamNumber][11].."  "..udpStreamTable[udpStreamNumber][12])
                        end
                    end



                    if(pinfo.abs_ts ~= nil) --终结时间
                    then
                        udpStreamTable[udpStreamNumber][14] = pinfo.abs_ts
                    end
                                         

                else  
                    

                    dataSize = dataSize + udpLenNumber -8

                    --print(udpStreamNumber)
                    udpStreamTable[udpStreamNumber] = {pcapFileName,udpStreamNumber-1,0,srcIPString,srcUdpPortString,dstIPString,dstUdpPortString,"UDP","UDP",udpLenNumber-8,udpLenNumber-8,0,pinfo.abs_ts,pinfo.abs_ts,0.000}
                    udpUserIP[udpStreamNumber] = srcIPString
                    udpServerIP[udpStreamNumber] = dstIPString

                    udpStreamSizeForATimeTable[udpStreamNumber] = {{}}
                    udpStreamSizeForATimeTable[udpStreamNumber][pinfo.number] = {pinfo.rel_ts,udpLenNumber -8,udpLenNumber-8,0,udpLenNumber+34,0,pinfo.number}

                    
                end  
            end

        end  

        function pairsByKeys(t)--按照索引重新派寻函数      
            local a = {}   

            for n in pairs(t) do          
                a[#a+1] = n      
            end

            table.sort(a)

            local i = 0  

            return function()          
                i = i + 1
                --print(t[a[i]][1])          
                return a[i], t[a[i]]      
            end  

        end


        function fileExists(path) --判断文件是否存在函数

            local file = io.open(path, "rb")

            if(file) 
            then 
                file:close() 
            end

            return file ~= nil

        end

        function tap.draw() 
            local maxSizeStreamOfAllPcap = nil
            local startPoint = {}
            local endPoint = {}



            for k, v in pairs(udpStreamTable) --写入udp,求流量占比的百分比
            do  
                v[3] = v[10]/dataSize
                v[15] = v[14] - v[13]
                --print(v[13].."   "..v[14].."  "..v[15])
            end

            for k, v in pairs(udpStreamTable) 
            do  

                if(v[3] >= 0.5 and v[15] >= 10) --只输出占比前几的流量情况
                then

                    local startBlockCount = 0
                    local endBlockCount = 0

                    local sixPacketInfo = {}--存储六个报文信息，为了方便遍历相互之间的关系，可调整

                    local status = 1
                    local packetCountOfAStatus = {}--该状态下持续包数,如果超过一定的包数，则放弃该状态

                    local firstBlockSize = 0--第一个块的大小


                    for m, l in pairsByKeys(udpStreamSizeForATimeTable[v[2]+1])--单个udp流写入
                    do
                        
                        if(l[1] ~= nil) --why nil
                        then
                            
                            do
                                

                                if(l[6] == 0)--0表示上行，1表示下行
                                then
                                    if(l[5] > 500 and l[5] < 900)
                                    then

                                        startBlockCount = startBlockCount +1
                                        startPoint[startBlockCount] = l
                                        print("start  "..l[7])

                                    end

                                end


                                if(status == 1)
                                then
                                    if(l[6] == 1)
                                    then
                                        if(l[5] < 1392)
                                        then
                                            status = 2
                                            packetCountOfAStatus[status] = 0

                                        end

                                        if(l[5] == 1392)
                                        then
                                            status = 4
                                            packetCountOfAStatus[status] = 0
                                            --print("ssss")

                                        end

                                    end

                                    --没有考虑音频和视频同时结束情况,即两个结束是相邻的
                                    
                                elseif(status == 2)
                                then
                                    packetCountOfAStatus[status] = packetCountOfAStatus[status] +1

                                    if(packetCountOfAStatus[status] > 15)--chrome linux下面在一个状态下定义的包个数为5个，在android下面定义的包个数为15个
                                    then
                                        status = 1
                                        packetCountOfAStatus[status] = 0
                                    end

                                    if(l[6] == 0 and l[5] > 75 and l[5] < 88)--如果是第一个包，可以考虑将区间范围缩小
                                    then
                                        status = 3
                                        packetCountOfAStatus[status] = 0

                                    elseif(l[6] == 1 and l[5] > 100 and l[5] < 134)--如果是第一个包，可以考虑将区间范围缩小,目前获取到的最大的ack确认包为133个字节
                                    then
                                        status = 5

                                        if(startPoint[2] ~= nil)--通过判断说明endpoint 大于startpoint
                                        then
                                            endBlockCount = endBlockCount +1--这个时候已经可以记录报文结束点了
                                            endPoint[endBlockCount] = l
                                            print("end    "..(l[7]))
                                        end

                                    else
                                        status = 2
                                    end

                                    --考虑下需序号为3291的报文
                                elseif(status == 3)
                                then
                                    

                                    packetCountOfAStatus[status] = packetCountOfAStatus[status] +1

                                    if(packetCountOfAStatus[status] > 15)--chrome linux下面在一个状态下定义的包个数为5个，在android下面定义的包个数为15个
                                    then
                                        status = 1
                                        packetCountOfAStatus[status] = 0

                                    end

                                    if(l[6] == 0 and l[5] > 75 and l[5] < 88)
                                    then
                                        status = 3
                                    end

                                    if(l[6] == 1 and l[5] > 100 and l[5] < 134)--如果是第一个包，可以考虑将区间范围缩小,目前获取到的最大的ack确认包为133个字节
                                    then
                                        status = 5
                                        if(startPoint[2] ~= nil)--通过判断说明endpoint 大于startpoint
                                        then
                                            endBlockCount = endBlockCount +1--这个时候已经可以记录报文结束点了
                                            endPoint[endBlockCount] = l
                                            print("end    "..(l[7]))
                                        end
                                    end

                                elseif(status == 4)
                                then

                                    packetCountOfAStatus[status] = packetCountOfAStatus[status] +1

                                    if(packetCountOfAStatus[status] > 13)--参数可调节,连续13个上行确认报文
                                    then
                                        status = 5
                                        if(startPoint[2] ~= nil)--通过判断说明endpoint 大于startpoint
                                        then
                                            endBlockCount = endBlockCount +1--这个时候已经可以记录报文结束点了
                                            endPoint[endBlockCount] = l
                                            print("end    "..(l[7]))
                                        end

                                    elseif(l[6] == 0 and l[5] > 75 and l[5] < 88)
                                    then
                                        status = 4

                                    elseif(l[6] == 1 and l[5] < 1392)--这个时候突然出现下行的小于1392的报文，及时跳转到2状态
                                    then
                                        status = 2
                                        packetCountOfAStatus[status] = 0

                                    else
                                        
                                        packetCountOfAStatus[status] = 0--对于1，4状态的清零
                                        status = 1
                                        packetCountOfAStatus[status] = 0
         
                                    end


                                elseif(status == 5)
                                then

                                    if(l[6] == 1 and l[5] > 100 and l[5] < 134)--考虑到连续129个字节的情况，这种情况会造成连续多个end点,因此有这个判断,目前获取到的最大的ack确认包为133个字节
                                    then
                                        status = 5

                                    elseif(l[6] == 0 and l[5] > 75 and l[5] < 88)
                                    then
                                        status = 5

                                    else
                                        
                                        packetCountOfAStatus[status] = 0--对于1，5状态的清零暂时没有用处
                                        status = 1
                                        packetCountOfAStatus[status] = 0
         
                                    end

                                else
                                    print("status erro,status number:"..status)

                                end

                                
                        
                            end

                            
                        end
                    end


                    --一旦属于不同块的音视频交叉将对，结果产生影响

                
                    local aBlockSize = 0
                    local nBlockSize = 0
                    local blockCount = 1
                    local tableLength = table.maxn(startPoint)
                    local csvFile = io.open("iosTrainCsvFile/"..pcapFileName..".csv","w+b")--每一个报文的流表信息概况

                    csvFile:write("timeInterval")
                    csvFile:write(",")
                    csvFile:write("aBlockSize")
                    csvFile:write(",")
                    csvFile:write("aBlockBitPerSecond")
                    csvFile:write(",")
                    csvFile:write("nBlockSize")
                    csvFile:write(",")
                    csvFile:write("\n")

                   for m, l in pairsByKeys(udpStreamSizeForATimeTable[v[2]+1])
                   do
                        if(l[7] ~= nil and (blockCount + 1) <= tableLength)
                        then
                            

                            if(l[7] == startPoint[blockCount+1][7])
                            then

                                print(startPoint[blockCount+1][7])

                                csvFile:write(startPoint[blockCount+1][1] - startPoint[blockCount][1])
                                csvFile:write(",")
                                csvFile:write(aBlockSize)
                                csvFile:write(",")

                                if((startPoint[blockCount+1][1] - startPoint[blockCount][1]) ~= 0)
                                then
                                    csvFile:write(aBlockSize/(startPoint[blockCount+1][1] - startPoint[blockCount][1])/1000)
                                else
                                    csvFile:write("0")
                                end

                                csvFile:write(",")
                                csvFile:write(nBlockSize)
                                csvFile:write(",")
                                csvFile:write("\n")

                                aBlockSize = 0
                                blockCount = blockCount + 1
                            end
                            

                            if(l[7] > startPoint[blockCount][7] and l[7] < startPoint[blockCount+1][7] and l[6] == 1)--这样做导致了一个问题就是，就是有的音频报文正好就是1392结束的，而这个时候应该取第一个endpoint而不是第二个
                            then
                                aBlockSize = aBlockSize + l[5] - 42--因为记录的是整个报文长度，因此要去除以太网，tcp，以及ip的头部
                                nBlockSize = nBlockSize + l[5] - 42--因为记录的是整个报文长度，因此要去除以太网，tcp，以及ip的头部
                            end

                        else
                            print("erro:"..m)
                        end   

                    end


                end

            end

             --获取get之间的时间间隔或者相对于第一个get的时间

        end  
   
end
    --监听报文  
    packet_listener()  
       --tcpStreamTable =nil  
end