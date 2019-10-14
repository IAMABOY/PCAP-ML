# coding: utf-8
#!/usr/bin/env python

import ipaddress
import struct
import sys
import dpkt
import os
from asn1crypto import x509
import config
from dpkt import ssl
import traceback
import config

global logger
logger = config.getShareLogger()

def getTlsRecords(buf):
    """
    Attempt to parse one or more TLSRecord's out of buf
    :param buf: string containing SSL/TLS messages. May have an incomplete record on the end
    :return:  [TLSRecord] int, total bytes consumed, != len(buf) if an incomplete record was left at the end.
    Raises SSL3Exception.
    """
    i, n = 0, len(buf)
    msgs = []
 
    while i + 5 <= n:
        v = buf[i + 1:i + 3]
        if v in ssl.SSL3_VERSION_BYTES:
            try:
                msg = ssl.TLSRecord(buf[i:])
                msgs.append(msg)
            except dpkt.NeedData:
                break
        else:
            if i == 0:  ############################################ added
                raise ssl.SSL3Exception('Bad TLS version in buf: %r' % buf[i:i + 5])
            else:
                break
 
        i += len(msg)
 
    return msgs, i

 
# TLS  version
def checkTlsVersion(data):
    version2 = False
    version3 = False
 
    if len(data) > 2:
        # ssl
        tmp = struct.unpack("bbb", data[0:3])
    else:
        return version2, version3
 
    # SSL v2. OR Message body too short.
    if (tmp[0] & 0x80 == 0x80) and (((tmp[0] & 0x7f) << 8 | tmp[1]) > 9):
        version2 = True
    elif (tmp[1] != 3) or (tmp[2] > 3):  # 版本,SSL 3.0 or TLS 1.0, 1.1 and 1.2
        version3 = False
    elif (tmp[0] < 20) or (tmp[0] > 23):  # 类型错误
        pass
    else:
        version3 = True
 
    return version2, version3
 
 
def sslV2Length(data):
    tmp = struct.unpack("bbb", data[0:3])
    if tmp[2] == 0x01:
        # Client_hello.
        lens = (tmp[0] & 0x7f) << 8 | tmp[1]
        cipher_specs_size = (data[5] << 8) | data[6]
        if cipher_specs_size % 3 != 0:  # Cipher specs not a multiple of 3 bytes.
            return 0
 
        session_id_len = (data[7] << 8) | data[8]
        random_size = (data[9] << 8) | data[10]
        if lens < (9 + cipher_specs_size + session_id_len + random_size):
            return 0
        return lens + 2
 
    if tmp[2] == 0x04:
        # Server hello, Not processing
        lens = (tmp[0] & 0x7f) << 8 | tmp[1]
        return lens + 2
 
    return 0
 
 
def getTlsCerts(stream):
    if not stream:
        return []
    version2, version3 = checkTlsVersion(stream)
    if not (version2 or version3):
        logger.warning("NOT a ssl flow!!!")
        return []
 
    if (stream[0]) not in {20, 21, 22, 23}:
        logger.warning("Data weird!!! please check !!!", list(stream[:30]))
        return []

    try:
        records = []
        if version2:
            length = sslV2Length(stream)
            logger.info("SSv2 tls found. extra len:{}".format(length))
            records, bytes_used = getTlsRecords(stream[length:])
        if version3:
            records, bytes_used = getTlsRecords(stream)
    except dpkt.ssl.SSL3Exception as exception:
        logger.warning('exception while parsing TLS records: {0}'.format(exception))
        return []
    if len(records) > 1:
        logger.warning("SSL stream has many({}) records!".format(len(records)))
    certInfo = []
    for record in records:
        if record.type == 0x16:  # HandShake
            certInfo = parseTlsCerts(record.data, record.length)
            if certInfo:
                return certInfo#取到网站证书就返回，忽略后面的情况
        if record.type == 0x17:
            # application data
            pass
    return certInfo
 
 
def parseTlsCerts(data, record_length):
    certInfo=[]
    handshake_type = ord(data[:1])
    if handshake_type == 4:
        logger.info('Session Ticket is not implemented yet')
        return certInfo
 
    total_len_consumed = 0
    while total_len_consumed < record_length:
        if total_len_consumed > 0:
            logger.warning('erro,total_len_consumed:{},record_length{}'.format(total_len_consumed,record_length))
        buffers = data[total_len_consumed:]
        try:
            handshake = dpkt.ssl.TLSHandshake(buffers)
        except dpkt.ssl.SSL3Exception as exception:
            logger.warning('dpkt.ssl.SSL3Exception exception while parsing TLS handshake record: {0}'.format(exception))
            break
        except dpkt.dpkt.NeedData as exception:
            logger.warning('dpkt.dpkt.NeedData exception while parsing TLS handshake record: {0}'.format(exception))
            break
        try:
            ch = handshake.data
        except UnboundLocalError as exception:
            logger.warning('exception while parsing TLS handshake record: {0}'.format(exception))
            break
        total_len_consumed += handshake.length + 4
        if handshake.type == 11:  # TLSCertificate
            # ssl_servers_with_handshake.add(client)
            hd_data = handshake.data
            assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
            for i in range(len(hd_data.certificates)):
                try:
                    cert = x509.Certificate.load(hd_data.certificates[i])
                    if cert:
                        if cert.subject:
                            sujectInfoDic = cert.subject.native
                            if sujectInfoDic:
                                certInfo.append(sujectInfoDic.setdefault('organization_name'))
                                '''certInfo.append(sujectInfoDic.setdefault('country_name'))
                                certInfo.append(sujectInfoDic.setdefault('locality_name'))
                                certInfo.append(sujectInfoDic.setdefault('state_or_province_name'))
                                certInfo.append(sujectInfoDic.setdefault('common_name'))
                                certInfo.append(sujectInfoDic.setdefault('organizational_unit_name'))       

                        san = []
                        if cert.subject_alt_name_value:
                            for general_name in cert.subject_alt_name_value:
                                if general_name.name == 'dns_name':
                                    san.append(general_name.native)

                        certInfo.append(san)'''
                        return certInfo#此处由于只需要网站证书，所以return
                        #with open(cert['tbs_certificate']['subject'].native['common_name']+'.cer', 'wb')as fp:
                            #fp.write(cert.dump())
                except Exception as e:
                    logger.warning(traceback.format_exc())
    return certInfo

def getSNI(data):
    sni = None
    try:
        tls = dpkt.ssl.TLS(data)
        if len(tls.records) < 1:
            return

        handshake = dpkt.ssl.TLSHandshake(tls.records[0].data)
        client_hello = handshake.data
        if isinstance(client_hello, dpkt.ssl.TLSClientHello):
            for ext in client_hello.extensions:
                if (0 == ext[0]):
                    sni = ext[1][5:]
    except Exception as e:
        logger.warning('get sni erro:{}'.format(e))
    return sni
