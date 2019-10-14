CERT_PATH = "../../../pcapFile/2019/pcap_443b"
PCAP_PATH = "../../../pcapFile/2019/pcap_80"
HTML_PATH = "../../../pcapFile/2019/html"
JSON_PATH = ""
#.IGNORE : left
all:
	@grep -oP "^.+:\s*$$" Makefile
	@echo
help:
	@grep -A1 -P "^.+:\s*$$" Makefile
	@echo

CERT:
	sh getAllCertFromPcap.sh

SSL:
	python getSslCertOrg.py $(PCAP_PATH) $(CERT_PATH)


HTML:
	sh getAllHtmlFromPcap.sh

HTTP:
	python getHttpTitleAndDesc.py $(PCAP_PATH) $(HTML_PATH)