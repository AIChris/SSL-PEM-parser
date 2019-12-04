# SSL-PEM-parser
Domain hunter from ssl certificate (pem files)

2 Steps guide:


1. run to get the cert

./get.pem.sh google.com

and on ip 

./get.pem.sh 8.8.8.8

[ INFO-1 ] getting the cert for  8.8.8.8 

[ INFO ] checksum of the file

de0216b2f65d7233e7fc634eb7b3039b  8.8.8.8.pem


2. Parse the file / folders

python parse_pem_ssl.py google.com.pem

and on ip 

python parse_pem_ssl.py 8.8.8.8.pem 

Serial;		certbefore;		Certafter		numberOfCN	Level;			File
326357..1561;	2019-11-05 00:00:00;	2020-01-28 00:00:00;	11;		INFO expires day ;59;	8.8.8.8.pem;;dns.google;GTS CA 1O1

Exampel:
https://github.com/AIChris/SSL-PEM-parser/blob/master/1.png

show subject alternative name
https://github.com/AIChris/SSL-PEM-parser/blob/master/1.png
