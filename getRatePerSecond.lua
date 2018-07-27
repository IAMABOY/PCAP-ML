local args = { ... }--命令行参数列表
local fileName = {}--过滤器对象列表
-- 没有参数返回
if #args == 0 then
    return
end

for i, arg in ipairs(args) do--取tshark传进来的参数
    fileName[i] = arg
    --print(fileName[i])
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
            if(tcpStream ~= nil)
            then
                tcpStreamNumber = tcpStreamNumber +1 --lua下表从1开始,而流号从0开始

                if(tcpStreamTable[tcpStreamNumber])  --tcp处理流程
                then
                    --print(pinfo.hi)
                    --print(pinfo.lo)
                    dataSize = dataSize + tcpLenNumber

                    if(appProto ~= nil)
                    then
                        tcpStreamTable[tcpStreamNumber][9] = tostring(appProto)
                    end

                    tcpStreamTable[tcpStreamNumber][10] = tcpStreamTable[tcpStreamNumber][10]+tcpLenNumber

                    if(tcpUserIP[tcpStreamNumber] == srcIPString) --上行数据
                    then
                        tcpStreamTable[tcpStreamNumber][11]  = tcpStreamTable[tcpStreamNumber][11]+tcpLenNumber
                        
                    end
                    --else
                    if(tcpServerIP[tcpStreamNumber] == srcIPString) --下行数据
                    then
                        tcpStreamTable[tcpStreamNumber][12] = tcpStreamTable[tcpStreamNumber][12]+tcpLenNumber
                        --print(tcpStreamTable[tcpStreamNumber][12])
                    end

                    if(pinfo.abs_ts ~= nil) --终结时间
                    then
                        tcpStreamTable[tcpStreamNumber][14] = pinfo.abs_ts
                    end

                    if(pinfo.rel_ts ~= nil) --终结时间
                    then
                        tcpStreamSizeForATimeTable[tcpStreamNumber][pinfo.number] = {pinfo.rel_ts,tcpStreamTable[tcpStreamNumber][10],tcpStreamTable[tcpStreamNumber][11],tcpStreamTable[tcpStreamNumber][12]}
                        --print(pinfo.number.."   "..tcpStreamSizeForATimeTable[tcpStreamNumber][pinfo.number][1].."    "..tcpStreamSizeForATimeTable[tcpStreamNumber][pinfo.number][2])
                    end
                       

                else  
                    
                    dataSize = dataSize + tcpLenNumber

                    tcpStreamTable[tcpStreamNumber] = {pcapFileName,tcpStreamNumber-1,0,srcIPString,srcTcpPortString,dstIPString,dstTcpPortString,"TCP","TCP",tcpLenNumber,tcpLenNumber,0,pinfo.abs_ts,pinfo.abs_ts,0.000}
                    --tcpUserIP[tcpStreamNumber] = srcIPString
                    --tcpServerIP[tcpStreamNumber] = dstIPString
                    tcpUserIP[tcpStreamNumber] = srcIPString
                    tcpServerIP[tcpStreamNumber] = dstIPString
                    
                    tcpStreamSizeForATimeTable[tcpStreamNumber] = {{}}
                    tcpStreamSizeForATimeTable[tcpStreamNumber][pinfo.number] = {pinfo.rel_ts,tcpLenNumber,tcpLenNumber,0}


                end 
            end 

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
                        --print(udpStreamTable[3][11])

                        --if(pinfo.number == 11588)
                        --then
                       -- print("dd"..srcIPString.."  "..dstIPString.."  "..udpUserIP[udpStreamNumber].."  "..udpServerIP[udpStreamNumber])

                        --end

                    end
                    --else
                    if(udpServerIP[udpStreamNumber] == srcIPString) --下行数据
                    --if(udpServerIP[udpStreamNumber] == pinfo.hi) --下行数据
                    then

                    --if(pinfo.number == 38138 or pinfo.number == 38137 or pinfo.number == 11642)
                        --then
                        --print(srcIPString.."  "..dstIPString.."  "..udpUserIP[udpStreamNumber].."  "..udpServerIP[udpStreamNumber])

                    --end

                        udpStreamTable[udpStreamNumber][12] = udpStreamTable[udpStreamNumber][12]+udpLenNumber -8 
                        --print(udpStreamTable[3][12])
                    end



                    if(pinfo.abs_ts ~= nil) --终结时间
                    then
                        udpStreamTable[udpStreamNumber][14] = pinfo.abs_ts
                    end
                       
                    if(pinfo.rel_ts ~= nil) --终结时间
                    then
                        --print(tonumber(pinfo.number))
                        --print(pinfo.number)
                        udpStreamSizeForATimeTable[udpStreamNumber][pinfo.number]  = {pinfo.rel_ts,udpStreamTable[udpStreamNumber][10],udpStreamTable[udpStreamNumber][11],udpStreamTable[udpStreamNumber][12]}
                        --print(udpStreamTable[udpStreamNumber][10].."  "..udpStreamTable[udpStreamNumber][11].."  "..udpStreamTable[udpStreamNumber][12])
                    end

                else  
                    

                    dataSize = dataSize + udpLenNumber -8

                    --print(udpStreamNumber)
                    udpStreamTable[udpStreamNumber] = {pcapFileName,udpStreamNumber-1,0,srcIPString,srcUdpPortString,dstIPString,dstUdpPortString,"UDP","UDP",udpLenNumber-8,udpLenNumber-8,0,pinfo.abs_ts,pinfo.abs_ts,0.000}
                    udpUserIP[udpStreamNumber] = srcIPString
                    udpServerIP[udpStreamNumber] = dstIPString

                    --udpUserIP[udpStreamNumber] = pinfo.hi
                    --udpServerIP[udpStreamNumber] = pinfo.lo
                    --print(tcpServerIP[udpStreamNumber])

                    udpStreamSizeForATimeTable[udpStreamNumber] = {{}}
                    udpStreamSizeForATimeTable[udpStreamNumber][pinfo.number] = {pinfo.rel_ts,udpLenNumber -8,udpLenNumber-8,0}

                    --if(pinfo.number == 94 or pinfo.number == 11642)
                        --then
                        --print("sss"..srcIPString.."  "..dstIPString.."  "..udpUserIP[udpStreamNumber].."  "..udpServerIP[udpStreamNumber])

                    --end
                    
                end  
            end

        end  

        function pairsByKeys(t)      
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


        function fileExists(path)

            local file = io.open(path, "rb")

            if(file) 
            then 
                file:close() 
            end

            return file ~= nil

        end

        function tap.draw() 
            local maxSizeStreamOfAllPcap = nil

            if(fileExists("csvFile/maxSizeStreamOfAllPcap.csv"))--先判断文件存不存在，如果没有则创建
            then
                maxSizeStreamOfAllPcap = io.open("csvFile/maxSizeStreamOfAllPcap.csv","a")--所有报文的最大流的信息
            else
                maxSizeStreamOfAllPcap = io.open("csvFile/maxSizeStreamOfAllPcap.csv","a")--所有报文的最大流的信息
                maxSizeStreamOfAllPcap:write("文件名")
                maxSizeStreamOfAllPcap:write(",")
                maxSizeStreamOfAllPcap:write("流序号")
                maxSizeStreamOfAllPcap:write(",")
                maxSizeStreamOfAllPcap:write("PPS")
                maxSizeStreamOfAllPcap:write(",")
                maxSizeStreamOfAllPcap:write("k字节/秒")
                maxSizeStreamOfAllPcap:write(",")
                maxSizeStreamOfAllPcap:write("平均分组大小")
                maxSizeStreamOfAllPcap:write(",")
                maxSizeStreamOfAllPcap:write("\n")
            end

            


            local csvFile = io.open("csvFile/"..pcapFileName..".csv","w+b")--每一个报文的流表信息概况

            csvFile:write("报文名")
            csvFile:write(",")
            csvFile:write("流序号")
            csvFile:write(",")
            csvFile:write("流量占比")
            csvFile:write(",")
            csvFile:write("用户IP")
            csvFile:write(",")
            csvFile:write("用户端口")
            csvFile:write(",")
            csvFile:write("网络IP")
            csvFile:write(",")
            csvFile:write("网络端口")
            csvFile:write(",")
            csvFile:write("传输层协议")
            csvFile:write(",")
            csvFile:write("应用层协议")
            csvFile:write(",")
            csvFile:write("流量(btyes)")
            csvFile:write(",")
            csvFile:write("上行流量(btyes)")
            csvFile:write(",")
            csvFile:write("下行流量(btyes)")
            csvFile:write(",")
            csvFile:write("流起始时间")
            csvFile:write(",")
            csvFile:write("流结束时间")
            csvFile:write(",")
            csvFile:write("流持续时间")
            csvFile:write(",")
            csvFile:write("\n")

            for k, v in pairs(tcpStreamTable) --写入tcp,求流量占比的百分比
            do  
                v[3] = v[10]/dataSize
                v[15] = v[14] - v[13]
                --print(v[13].."   "..v[14].."  "..v[15])
            end

            for k, v in pairs(tcpStreamTable) 
            do  
                

                for i, j in pairs(v)
                do  
                    csvFile:write(j)
                    csvFile:write(",")
                end

                csvFile:write("\n")

                if(v[3] >= 0.7 and v[15] >= 10) --只输出占比前几的流量情况
                then

                    local tcpStreamDetailCsvFile = io.open("csvFile/"..pcapFileName.."_tcp_stream"..v[2]..".csv","w+b")--前面为了从lua下标1开始，加了1，这里要去除

                    tcpStreamDetailCsvFile:write("time")
                    tcpStreamDetailCsvFile:write(",")
                    tcpStreamDetailCsvFile:write("hi bytes")
                    tcpStreamDetailCsvFile:write(",")
                    tcpStreamDetailCsvFile:write("low bytes")
                    tcpStreamDetailCsvFile:write(",")
                    tcpStreamDetailCsvFile:write("label")
                    tcpStreamDetailCsvFile:write(",")
                    tcpStreamDetailCsvFile:write("\n")

                    local lastTcpSize = {0,0} --时间序列0,1，2，3，4
                    local currentTcpSize = {0,0}
                    local lastTcpTimePoint = 0
                    local currentTcpTimePoint = 0
                    local lastLastTcpSize = {0,0};
                    --local cycleTime = 0

                    for m, l in pairsByKeys(tcpStreamSizeForATimeTable[v[2]+1])--单个tcp流写入
                    do
                        --print(table.maxn(tcpStreamSizeForATimeTable[v[2]]))
                        if(l[1] ~= nil) --why nil
                        then

                            currentTcpTimePoint = math.ceil(l[1])
                            currentTcpSize[1] = l[3]
                            currentTcpSize[2] = l[4]

                            if(currentTcpTimePoint > lastTcpTimePoint)
                            then
                                --cycleTime = currentTimePoint - lastTimePoint

                                for z = lastTcpTimePoint,currentTcpTimePoint-1
                                do
                                    
                                    --print(currentUdpSize)
                                    tcpStreamDetailCsvFile:write(z)
                                    tcpStreamDetailCsvFile:write(",")
                                    if(z == lastTcpTimePoint and lastTcpTimePoint ~= 0)
                                    then
                                        tcpStreamDetailCsvFile:write(lastTcpSize[1] -lastLastTcpSize[1])
                                        tcpStreamDetailCsvFile:write(",")
                                        tcpStreamDetailCsvFile:write(lastTcpSize[2] -lastLastTcpSize[2])
                                    else
                                        tcpStreamDetailCsvFile:write(0)
                                        tcpStreamDetailCsvFile:write(",")
                                        tcpStreamDetailCsvFile:write(0)
                                    end

                                    tcpStreamDetailCsvFile:write(",")
                                    tcpStreamDetailCsvFile:write(0)
                                    tcpStreamDetailCsvFile:write(",")
                                    tcpStreamDetailCsvFile:write("\n")
                                end


                                lastLastTcpSize[1] = lastTcpSize[1]
                                lastLastTcpSize[2] = lastTcpSize[2]
                            end

                            if(m == table.maxn(tcpStreamSizeForATimeTable[v[2]+1]))
                            then
                                --print(m)
                                tcpStreamDetailCsvFile:write(currentTcpTimePoint)
                                tcpStreamDetailCsvFile:write(",")
                                tcpStreamDetailCsvFile:write(currentTcpSize[1]-lastLastTcpSize[1])
                                tcpStreamDetailCsvFile:write(",")
                                tcpStreamDetailCsvFile:write(currentTcpSize[2]-lastLastTcpSize[2])
                                tcpStreamDetailCsvFile:write(",")
                                tcpStreamDetailCsvFile:write(0)
                                tcpStreamDetailCsvFile:write(",")
                                tcpStreamDetailCsvFile:write("\n")
                            end

                            lastTcpSize[1] = currentTcpSize[1]
                            lastTcpSize[2] = currentTcpSize[2]
                            lastTcpTimePoint = currentTcpTimePoint

                            --print(math.ceil(l[1]))
                        end
                        
                    end
                end

            end

            for k, v in pairs(udpStreamTable) --写入udp,求流量占比的百分比
            do  
                v[3] = v[10]/dataSize
                v[15] = v[14] - v[13]
                --print(v[13].."   "..v[14].."  "..v[15])
            end

            for k, v in pairs(udpStreamTable) 
            do  
                

                for i, j in pairs(v)
                do  
                    csvFile:write(j)
                    csvFile:write(",")
                end

                csvFile:write("\n")

                if(v[3] >= 0.7 and v[15] >= 10) --只输出占比前几的流量情况
                then

                    

                    local udpStreamDetailCsvFile = io.open("csvFile/"..pcapFileName.."_udp_stream"..v[2]..".csv","w+b")--前面为了从lua下标1开始，加了1，这里要去除

                    udpStreamDetailCsvFile:write("time")
                    udpStreamDetailCsvFile:write(",")
                    udpStreamDetailCsvFile:write("hi bytes")
                    udpStreamDetailCsvFile:write(",")
                    udpStreamDetailCsvFile:write("low bytes")
                    udpStreamDetailCsvFile:write(",")
                    udpStreamDetailCsvFile:write("label")
                    udpStreamDetailCsvFile:write(",")
                    udpStreamDetailCsvFile:write("\n")

                    local lastUdpSize = {0,0} --时间序列0,1，2，3，4
                    local currentUdpSize = {0,0}
                    local lastUdpTimePoint = 0
                    local currentUdpTimePoint = 0
                    local lastLastUdpSize = {0,0};
                    --local cycleTime = 0
                    local packetCount =0

                    for m, l in pairsByKeys(udpStreamSizeForATimeTable[v[2]+1])--单个udp流写入
                    do
                        
                        if(l[1] ~= nil) --why nil
                        then
                            packetCount  = packetCount +1
                            currentUdpTimePoint = math.ceil(l[1])--ceil取整数部分，只要存在小数，自动加1
                            currentUdpSize[1] = l[3]
                            currentUdpSize[2] = l[4]
                            
                            --print(math.ceil(2.0517))
                            if(currentUdpTimePoint > lastUdpTimePoint )
                            then
                                --cycleTime = currentTimePoint - lastTimePoint
                                
                                --print(m.."  "..lastUdpSize.."  "..currentUdpSize.."  "..currentUdpTimePoint.."  "..l[1])


                                for z = lastUdpTimePoint,currentUdpTimePoint-1
                                do
                                    
                                    --print(currentUdpSize)
                                    udpStreamDetailCsvFile:write(z)
                                    udpStreamDetailCsvFile:write(",")
                                    if(z == lastUdpTimePoint and lastUdpTimePoint ~= 0)
                                    then
                                        udpStreamDetailCsvFile:write(lastUdpSize[1] -lastLastUdpSize[1])
                                        udpStreamDetailCsvFile:write(",")
                                        udpStreamDetailCsvFile:write(lastUdpSize[2] -lastLastUdpSize[2])
                                    else
                                        udpStreamDetailCsvFile:write(0)
                                        udpStreamDetailCsvFile:write(",")
                                        udpStreamDetailCsvFile:write(0)
                                    end
                                    
                                    udpStreamDetailCsvFile:write(",")
                                    udpStreamDetailCsvFile:write(0)
                                    udpStreamDetailCsvFile:write(",")
                                    udpStreamDetailCsvFile:write("\n")
                                end


                                lastLastUdpSize[1] = lastUdpSize[1]
                                lastLastUdpSize[2] = lastUdpSize[2]
                            end

                            if(m == table.maxn(udpStreamSizeForATimeTable[v[2]+1]))
                            then
                                --print(m)
                                udpStreamDetailCsvFile:write(currentUdpTimePoint)
                                udpStreamDetailCsvFile:write(",")
                                udpStreamDetailCsvFile:write(currentUdpSize[1]-lastLastUdpSize[1])
                                udpStreamDetailCsvFile:write(",")
                                udpStreamDetailCsvFile:write(currentUdpSize[2]-lastLastUdpSize[2])
                                udpStreamDetailCsvFile:write(",")
                                udpStreamDetailCsvFile:write(0)
                                udpStreamDetailCsvFile:write(",")
                                udpStreamDetailCsvFile:write("\n")
                                --print(packetCount) 
                                --print(table.maxn(udpStreamSizeForATimeTable[v[2]+1]).."  "..#udpStreamSizeForATimeTable[v[2]+1].."  "..table.maxn(udpStreamSizeForATimeTable[v[2]]).."  "..#udpStreamSizeForATimeTable[v[2]])

                                --print("sss"..currentUdpSize[1].."  "..lastUdpSize[1].."  "..currentUdpSize[2].."  "..lastUdpSize[2].."  "..lastLastUdpSize[2].."  "..lastLastUdpSize[2])
                            end
                            --print(currentUdpSize[1].."  "..lastUdpSize[1].."  "..currentUdpSize[2].."  "..lastUdpSize[2])
                            lastUdpSize[1] = currentUdpSize[1]
                            lastUdpSize[2] = currentUdpSize[2]
                            lastUdpTimePoint = currentUdpTimePoint
                            --lastUdpSize = currentUdpSize
                            
                            --print(math.ceil(l[1]))
                        end
                        
                    end

                    do --该代码块单次写入每一报文中占比最大的那条流的信息
                        maxSizeStreamOfAllPcap:write(pcapFileName)
                        maxSizeStreamOfAllPcap:write(",")
                        maxSizeStreamOfAllPcap:write(v[2])
                        maxSizeStreamOfAllPcap:write(",")
                        maxSizeStreamOfAllPcap:write(math.ceil(packetCount/v[15])-1)
                        maxSizeStreamOfAllPcap:write(",")
                        maxSizeStreamOfAllPcap:write(math.ceil(v[10]/v[15]/1024)-1)
                        maxSizeStreamOfAllPcap:write(",")
                        maxSizeStreamOfAllPcap:write(math.ceil(v[10]/packetCount)-1)--这里面统计packetCount，而不是使用#(udpStreamSizeForATimeTable[v[2]+1])的原因在于使用#(udpStreamSizeForATimeTable[v[2]+1])统计的数组长度不准确
                        maxSizeStreamOfAllPcap:write(",")
                        maxSizeStreamOfAllPcap:write("\n")
                        print(v[10].."  "..v[15].."  "..packetCount.."  "..table.maxn(udpStreamSizeForATimeTable[v[2]+1]).."  "..#(udpStreamSizeForATimeTable[v[2]+1])) 
                        --maxSizeStreamOfAllPcap:close()
                    end

                end

            end
            --关闭所有打开的文件
            --csvFile:close()
            --maxSizeStreamOfAllPcap:close()
            --tcpStreamDetailCsvFile:close() 
            --udpStreamDetailCsvFile:close() 
            --结束执行  
            --print("tap.draw")  
        end  
    end  
       --监听报文  
    packet_listener()  
       --tcpStreamTable =nil  
end  