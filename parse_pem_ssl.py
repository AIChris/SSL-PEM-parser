# -*- coding: utf-8 -*-
# todo json putput...print cn/org...

import sys, os, time
from OpenSSL.crypto import load_certificate, FILETYPE_PEM # for load_certificate
import ssl
from pprint import pprint as pp
import getopt
import datetime
from datetime import datetime, timedelta
# import re

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

PRINT_subjectAltName 	= False
PRINT_ERROR 			= False
NumberOfCN				= 0
KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KBLUE = '\x1b[34m'
KPURPLE = '\x1b[35m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

def bold(text):
    return KBOLD + text + KNORM

def red(text):
    return KRED + text + KNORM

def green(text):
    return KGREEN + text + KNORM

def yellow(text):
    return KYELLOW + text + KNORM

def blue(text):
    return KBLUE + text + KNORM

def purple(text):
    return KPURPLE + text + KNORM

def cyan(text):
    return KCYAN + text + KNORM


def helpMe():
	print "helper input is req... pleas provide a pem file or a folder to scan for .pem files "
	print " "
	print "-cn print subjectAltName"
	print "----------------to get pem file...-----------------------"
	print "openssl s_client -showcerts -connect google.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM  > google.com.pem" 
	print "and for mail "
	print "openssl s_client -connect smtp.gmail.com:587 -starttls smtp </dev/null 2>/dev/null|openssl x509 -outform PEM >smtp.gmail.com.pem"
	print ""

def Convert(string): 
    li = list(string.split(",")) 
    return li 

def parsePEM(pemIN):
	global NumberOfCN
	NumberOfCN = 0
	if PRINT_ERROR:
		print "Parsing this file: " + str(pemIN)
	statinfo = os.stat(pemIN)


	if statinfo.st_size == 0:
		if PRINT_ERROR:
			print "[- Error st_size ] the file is have a size of 0 "  + str (pemIN)
		return 
		
	try:
		cert_dict = ssl._ssl._test_decode_cert(pemIN)
	except Exception, e:
		if PRINT_ERROR:
			print "[- Error parsing ] " + str (e) + str (" File ") + str (pemIN)
		exit(0)
	
	certDatadict  = cert_dict
	# lacy way to open againnn
	cert = load_certificate(FILETYPE_PEM, open(pemIN).read())
	# https://stackoverflow.com/questions/30862099/how-can-i-get-certificate-issuer-information-in-python

	subject  = cert.get_subject()
	issued_to = subject.CN 
	issuer = cert.get_issuer()
	issued_by = issuer.CN

	certSerial = cert.get_serial_number()
	certSerialShort  = str(certSerial)[0:6] + str("..") +str(certSerial)[-4:]

	CN_DNS_DOMAINS = ""
	for i in range(0, cert.get_extension_count() - 1):
		try:
			if "DNS:" in str(cert.get_extension(i)):
				CN_DNS = str(cert.get_extension(i)).replace("DNS:","").replace(", ",",")
				CN_DNS_DOMAINS = Convert(CN_DNS)
				xi = 0
				if PRINT_subjectAltName:
					for x in CN_DNS_DOMAINS:
						xi +=1
						print str(certSerialShort) +str(";CN;")+ str(xi) + str(";CN\t;") + str(x) 
		except Exception, e:
			print "[ERROR parsing... get_extension] on this file: " +str(pemIN)  + str ("; ") + str(i) +str(" Error MSG:") + str(e)

	currentcertnotAfter  = cert.get_notAfter()
	currentcertnotBefore  = cert.get_notBefore()

	today = time.strftime("%Y%m%d", time.localtime(time.time()))
	someDay  = currentcertnotAfter.replace("Z","")[0:8] 
	date_format = "%Y%m%d"
	a = datetime.strptime(someDay, date_format)
	b = datetime.strptime(today, date_format)
	delta = a - b
	certbefore = str(datetime.strptime(currentcertnotBefore.replace("Z","")[0:8] , "%Y%m%d"))
	certafter  = str(datetime.strptime(currentcertnotAfter.replace("Z","")[0:8] , "%Y%m%d"))

	if subject.CN == None:
		issued_to = u"None"

	if issued_by == None:
		issued_by = u"None"

	if 10 > delta.days:
		msg3 = "CRITICAL expired ;" + str(delta.days)
		sys.stdout.write(str(certSerialShort) +str(";\t") + str(certbefore) + str(";\t") + str (certafter) + str(";\t")+ str(len(CN_DNS_DOMAINS)) + str(";\t\t") + red(msg3)   + str(";\t")+ str(pemIN)+ str(";")  + str(";") + issued_to +str(";")+ issued_by + str("\n")) ##+ str("\t")+ str(pemIN)+ str(";")  + str(str(";")+str(subject.CN) +str(";")+ (issued_by)+ "\n"))   #+ str (certBefore)
		sys.stdout.flush()
	elif 30 >  delta.days:
		msg3 = "WARNING soon exp ;"+ str(delta.days)
		sys.stdout.write(str(certSerialShort) +str(";\t") + str(certbefore) + str(";\t") + str (certafter) + str(";\t")+ str(len(CN_DNS_DOMAINS)) + str(";\t\t")+ yellow(msg3) + str(";\t")+ str(pemIN)+ str(";")  + str(";") + issued_to +str(";")+ issued_by + str("\n"))
		sys.stdout.flush()
	elif delta.days == 0:
		print "Delta 0 "+ str(delta.days)
	else:
		msg3 = "INFO expires day ;"+ str(delta.days)
		sys.stdout.write(str(certSerialShort) +str(";\t") + str(certbefore) + str(";\t") + str (certafter) + str(";\t")+ str(len(CN_DNS_DOMAINS))+ str(";\t\t")+  green(msg3)  + str(";\t")+ str(pemIN)+ str(";")  + str(";") + issued_to +str(";")+ issued_by + str("\n"))
		sys.stdout.flush()


if __name__ == '__main__':
	if len(sys.argv) == 1:
		helpMe()
		sys.exit(-1)
	try:
		opts, args = getopt.getopt(sys.argv,"hM:w:u:p:e:l:H:x:",["mode=","filename=","docuri=","port=","payloadurl=","payloadlocation=","customhta=","obfuscate="])
	except getopt.GetoptError:
		print 'Usage: python '+sys.argv[0]+' -h'
		exit(0)

	for arg in args:
		if str(arg) == '-cn':
			PRINT_subjectAltName = True
		if str(arg) == '-cn':
			PRINT_subjectAltName = True
		if str(arg) == '-debug':
			PRINT_ERROR = True

	PEM_PATH = str(sys.argv[1])

	if os.path.isfile(PEM_PATH):
		print "Serial;\t\tcertbefore;\t\tCertafter\t\tnumberOfCN\tLevel;\t\t\tFile"
		parsePEM(PEM_PATH)
	else:
		if not os.path.isdir(sys.argv[1]):
			print "looks like a dir or... I can not get the files so I do exit path is : " + str(os.getcwd())+ str(sys.argv[1])
			exit(0)
		print "Serial;\t\tcertbefore;\t\tCertafter\t\tnumberOfCN\tLevel;\t\t\tFile"
		for path, subdirs, files in os.walk(PEM_PATH):
			for name in files:
				if "pem" in name:
					parsePEM(str(path) +str("/")+ name)