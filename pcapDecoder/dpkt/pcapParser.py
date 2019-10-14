# coding: utf-8
#!/usr/bin/env python
import sys
import os
import dpkt
import sslCertInfoParser
import config
import socket
import struct
import gc 

global buffer
buffer = config.getShareVar()

global tupleSet
tupleSet = set()

global logger
logger = config.getShareLogger()

def checkIfSSL(tcp):
    if 443 != tcp.dport:
        return False

    data = tcp.data
    version2 = False
    version3 = False
    ifHandshake = False
    ifClientHello = False

    if len(data) > 6:
        tmp = struct.unpack("bbbbbb", data[0:6])
    else:
        return False
 
    # SSL v2. OR Message body too short.
    if (tmp[0] & 0x80 == 0x80) and (((tmp[0] & 0x7f) << 8 | tmp[1]) > 9):
        version2 = True
    if (tmp[1] == 3) and (tmp[2] < 4):  # 版本,SSL 3.0 or TLS 1.0, 1.1 and 1.2
        version3 = True
    if (24 > tmp[0] > 19):  # 类型
        ifHandshake = True

    if (1 == tmp[5]):  # 类型
        ifClientHello = True

    return ((version2 or version3) and ifHandshake and ifClientHello)


def checkIfHTTP(tcp):
    if (80 != tcp.sport and 80 != tcp.dport) and (8080 != tcp.sport and 8080 != tcp.dport):
        return False

    data = tcp.data

    if len(data) < 4:
        return False

    if data[:4] == str.encode('HTTP'):
        return True

    return False

def recordQuadrTupleForm(ip):
    srcTwoTuple = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    dstTwoTuple = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    tcp = ip.data
    if checkIfSSL(tcp):#1,探针取SSL报文规则,完整流or不完整流;2,探针取HTTP报文规则,完整流or不完整流
        quadrTupleForm = "{}-{}".format(dstTwoTuple, srcTwoTuple)
        global tupleSet
        global buffer
        if quadrTupleForm not in tupleSet:
            tupleSet.add(quadrTupleForm)
            buffer[quadrTupleForm] = [{"out":[], "in":[]}]
        else:
            logger.info("found multi connection of a tcp flow!connection key:{}".format(quadrTupleForm))
            buffer[quadrTupleForm].append({"out":[], "in":[]})

    else:   
        pass

def recordTcpData(ip, stream, nth, timestamp):
    global buffer
    global tupleSet
    srcTwoTuple = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    dstTwoTuple = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    if "{}-{}".format(srcTwoTuple, dstTwoTuple) in tupleSet:  # OUT flow
        quadrTupleForm = "{}-{}".format(srcTwoTuple, dstTwoTuple)
        buffer[quadrTupleForm][-1]["in"].append((ip.data.sport, nth, timestamp, bytearray(stream)))
    elif "{}-{}".format(dstTwoTuple, srcTwoTuple) in tupleSet:  # IN flow
        quadrTupleForm = "{}-{}".format(dstTwoTuple, srcTwoTuple)
        buffer[quadrTupleForm][-1]["out"].append((ip.data.dport, nth, timestamp, bytearray(stream)))
  

def tcpPacketParser(ip, nth, timestamp):
    recordQuadrTupleForm(ip)
    stream = ip.data.data
    if len(stream):
        recordTcpData(ip, stream, nth, timestamp)
 
def ipPacketParser(ip, nth, timestamp):
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcpPacketParser(ip, nth, timestamp)
        

def decodePacket(packet, nth, timestamp):
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        ipPacketParser(eth.data, nth, timestamp)

def pcapReader(filename):
    global buffer
    try:
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)#dpkt如何限制每一条流只取前10个报文
            i = 1
            for timestamp, packet in capture:
                decodePacket( packet, i, timestamp)
                i += 1
 
            logger.info("file:{} found {} different flows total!!!".format(filename,len(buffer)))

    except Exception as e:
        logger.warning('parse {}, error:{}'.format(filename, e))


def getSslAndHttpInfo():
    global buffer
    for quadrTupleForm, flows in buffer.items():
        for raw_flow in flows:
            # logger.info(raw_flow)
            flow = {"connection": quadrTupleForm, "payload": {"in": raw_flow["in"], "out": raw_flow["out"]}}
            in_payload = bytearray() # bytes is immutable. Use bytearray.
            out_payload = bytearray() # bytes is immutable. Use bytearray.
            port = 0

            for port, nth, timestamp, payload in flow["payload"]["in"]:  
                in_payload.extend(payload)

            for port, nth, timestamp, outpayload in flow["payload"]["out"]:  
                out_payload.extend(outpayload)
                break#只取clienthello的报文，因此只取第一个包
                    
            if 443 == port:
                certInfo = sslCertInfoParser.getTlsCerts(bytes(in_payload))
                sni = sslCertInfoParser.getSNI(bytes(out_payload))

                if sni:
                    logger.info("SNI:{},certInfo:{}".format(sni,certInfo))
                    #添加数据库程序
                    print("SNI:{},certInfo:{}".format(sni,certInfo))
            elif 80 == port or 8080 == port:
                #httpHtmlInfoParser.getHttpHtmlInfo(bytes(in_payload))
                pass
            else:
                pass
 
if __name__ == "__main__":
    if len (sys.argv) < 2:
        logger.info('HELP: python {} <PCAP_PATH>'.format(sys.argv[0]))
        sys.exit(0)
        #_EXIT_
    pcapFilePath = sys.argv[1]

    filename = pcapFilePath + str(os.path.sep) + 'ssl.pcap'
    filename = pcapFilePath

    if filename:
        pcapReader(filename)
        getSslAndHttpInfo()
        del buffer
        gc.collect()