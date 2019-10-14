local args = { ... }--命令行参数列表
local fields = {}--过滤器对象列表
--文件名字信息字段
local getSslServerName = Field.new("ssl.handshake.extensions_server_name")
local getTcpStream = Field.new("tcp.stream")
local getSrcIp = Field.new("ip.src")
local getDstIp = Field.new("ip.dst")
local getSrcPort = Field.new("tcp.srcport")
local getDstPort = Field.new("tcp.dstport")
local getIpVersion = Field.new("ip.version")


local fileNameTable = {}--以每一条流为索引的文件名数组
local fileContent = {}--以每一条流为索引的文件句柄数组


-- 没有参数返回
if #args < 2 then
    print("erro,cmd format:tshark -X lua_script:test.lua -X lua_script1:testFileName -X lua_script1:filter -r testFileName.pcap -q")
    return
end


folderPath = args[1]
dataFilter = Field.new(args[2])


--for i, arg in ipairs(args) do
    --fields[i] = Field.new(arg)
--end

--local cert_file = io.open("cert.cer", "wb")

do
    local function packet_listener()
        local tap = Listener.new("frame", "tcp.port == 443 ")--frame是监听器的名称，tcp是wireshark过滤器规则  

        function tap.reset()
            --print("tap reset")
        end

        local function hex(ascii_code)
            -- 将一个十六进制字符转化为对应的数值
            if not ascii_code then
                return 0
            elseif ascii_code < 58 then
                return ascii_code - 48
            elseif ascii_code < 91 then
                return ascii_code - 65 + 10
            else
                return ascii_code - 97 + 10
            end
        end

       tobinary = function (hexbytes)
        -- 将字符转形式的十六进制转化为对应的码流形式

            local binary = {}
            local sz = 1

            for i=1, string.len(hexbytes), 2 do
                binary[sz] = string.char( 16 * hex( string.byte(hexbytes,i) ) + hex( string.byte(hexbytes,i+1) ) )
                sz = sz + 1
            end

            return table.concat(binary)

        end

        function tap.packet(pinfo,tvb)

            local tcpStreamNumber = tostring(getTcpStream())

            if(getSslServerName() ~= nil) then

                local sslServerName = getSslServerName()
                local tcpStream = getTcpStream()
                local srcIp = getSrcIp()
                local dstIp = getDstIp()
                local srcPort = getSrcPort()
                local dstPort = getDstPort()
                local ipVersion = getIpVersion()
                

                if(fileNameTable[tcpStreamNumber]) then
                   --print(tcpStreamNumber..":".."fileNameTable[tcpStreamNumber] not NULL")
                else
                    local certFileName = tostring(sslServerName).."_"..tostring(tcpStream).."_"..tostring(srcIp).."_"..tostring(srcPort).."_"..tostring(dstIp).."_"..tostring(dstPort).."_"..tostring(ipVersion)..".cer"

                    fileNameTable[tcpStreamNumber] = certFileName
       
                    --print(type(fileNameTable[tcpStreamNumber]),type(tcpStreamNumber),type(fileContent[tcpStreamNumber]),type(fileNameTable))
                end
            end

            
            fieldInfo = dataFilter()
            if fieldInfo ~= nil then 
                local fieldTvbRange = fieldInfo.range

                if(nil ~= fileNameTable[tcpStreamNumber]) then 
                    if(nil == fileContent[tcpStreamNumber]) then

                        fileContent[tcpStreamNumber] = tostring(fieldTvbRange:bytes())
                        --fileContent[tcpStreamNumber] = io.open(folderPath.."/"..fileNameTable[tcpStreamNumber], "wb")
                       
                        --print(folderPath.."/"..fileNameTable[tcpStreamNumber]) 
                        --print("fileContent:"..tcpStreamNumber)
                        --os.execute("sleep " .. 3)
                        --print(tcpStreamNumber)

                    else
                        fileContent[tcpStreamNumber] = fileContent[tcpStreamNumber]..tostring(fieldTvbRange:bytes())
                    end


                else
                    return 
                end
                
            end

           
        end

        function tap.draw()
            --结束执行 
            
            fileHandlerLength =0 
            fileNameTableLength =0 

            for key, value in pairs(fileContent) do
                fileHandlerLength = fileHandlerLength + 1
            end

            for key, value in pairs(fileNameTable) do

                if(fileContent[key] ~= nil) then
                    --print(key, value,fileContent[key])

                    fileHandler = io.open(folderPath.."/"..value, "wb")
                    if(fileHandler ~= nil) then
                        fileHandler:write(tobinary(fileContent[key]))
                        fileHandler:close()
                    else
                        print(value.." open erro")
                    end
                end

                fileNameTableLength = fileNameTableLength + 1
            end

            print("fileContent length:"..fileHandlerLength)
            print("fileNameTable length:"..fileNameTableLength)

            fileContent = nil
            fileNameTable = nil
        end
    end
    --监听报文  
    packet_listener()
end
