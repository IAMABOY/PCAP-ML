# coding: utf-8
#!/usr/bin/env python

import commFunc

class ShareVar:
	buffer = {}

def getShareVar():
	return ShareVar.buffer

def setShareVar():
	ShareVar.buffer = {}


class ShareLogger:
	logger = commFunc.initLogger('log1111.txt',True,True)


def getShareLogger():
	#ShareLogger.logger = commFunc.initLogger('log1111.txt',True)
	return ShareLogger.logger

def setShareLogger(logger):
	ShareLogger.logger = logger

