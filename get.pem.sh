
# Source https://github.com/AIChris/SSL-PEM-parser
# Simpel script to get the ssl/tls pem file from a site/ip.

if [ -z "$1" ]

then
	echo "Pleas give me a site / ip "
	echo ""
	echo "and for the smtp:587 if any... todo..."    
	echo ""
	echo "How to run manual..."
	echo "openssl s_client -showcerts -connect XXX:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > XXX.pem  "
	echo "openssl s_client -connect XXX:587 -starttls smtp </dev/null 2>/dev/null|openssl x509 -outform PEM > XXX.pem"
else
	
if [ -f "$1" ]; then
   echo "File $1 exists try to loop over the file..."
   mkdir SSL_OUT_FILE_$1

cat $1 | grep -v "#" | while read line
do
	echo "Try to get this one... " $line
	openssl s_client -showcerts -connect $line:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > SSL_OUT_FILE_$1/$line.pem
done
   
else
	myPi=`echo $1 | grep -i "https://"`

	if [ $myPi > 3 ];
	then 
	    echo "[ INFO-0 ] getting the certs for  $1 but have  filter out URL"
		URL1=`echo $1 |cut -d"/" -f3`

		set -- $URL1 # to change the first argument...
		openssl s_client -showcerts -connect $1:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > $1.pem
	else

		echo "[ INFO-1 ] getting the cert for  $1 "
		openssl s_client -showcerts -connect $1:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > $1.pem
	#	openssl s_client -connect $1:587 -starttls smtp </dev/null 2>/dev/null|openssl x509 -outform PEM >$1.pem
	fi;	


	
	if [ -s $1.pem ]
	then
		echo "[ INFO ] checksum of the file"
		md5sum $1.pem
	else
		echo "[ ERROR ] emty File"	
	fi
fi
fi
