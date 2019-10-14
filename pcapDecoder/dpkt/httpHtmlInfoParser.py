# coding: utf-8
#!/usr/bin/env python
import sys
import dpkt
import os
from bs4 import BeautifulSoup

import config

global logger
logger = config.getShareLogger()

def getTitleDescKeyWords(htmlFileContent):
    # “<title></title>”
    soup = BeautifulSoup(htmlFileContent, 'lxml')
    title = None
    description = None
    keywords = None

    if soup:
        if soup.title:
            title = soup.title.get_text()

        # “<meta name="description" content="">”
        soupDesc = soup.find(name='meta', attrs={"name":"description"})
        if soupDesc:
            description = soupDesc.get('content','')

        # “<meta name="keywords" content="">”
        soupKey = soup.find(name='meta', attrs={"name":"keywords"})
        if soupKey:
            keywords = soupKey.get('content','')  

    if None == title and None == description and None == keywords:
        return None
    return [title,description,keywords]

def getHttpHtmlInfo(stream):
    try:
        if len(stream) < 4:
            return

        if stream[:4] == str.encode('HTTP'):#只解析下行报文
            httpRespons = dpkt.http.Response(stream)

            if httpRespons:
                httpHeaders = httpRespons.headers
                htmlInfo = None

                if  'gzip' == httpHeaders.setdefault('content-encoding'):
                    htmlGzip = dpkt.gzip.Gzip(httpRespons.body)
                    #decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    #httpBody = decompressor.decompress(httpRespons.body)
                    httpBody = htmlGzip.decompress()
                else:
                    httpBody = httpRespons.body

                htmlInfo = getTitleDescKeyWords(httpBody)

                if htmlInfo:
                    print(htmlInfo)

        else:
            logger.warning('exception only accept http response: {0}'.format(stream[:4]))
            pass
    except dpkt.dpkt.NeedData as exception:
        logger.warning('dpkt.dpkt.NeedData exception while parsing HTTP: {0}'.format(exception))#short body (missing 72080 bytes), 这种情况需要考虑吗?
    except Exception as exception:
        logger.error('exception while parsing HTTP: {0}'.format(exception))
