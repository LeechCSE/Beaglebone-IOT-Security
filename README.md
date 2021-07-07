Beaglebone: IOT security
===
CS 111: Operating System Principles  
Summer 2018  
  
Included files:
* tcp.c - source code in C-language that via TCP connection reports and
  	      	logs real-time temperature measured by BBG temperature
		sensor(v1.2) and receives and processes commands from the
		lever.cs.ucla.edu TCP server(port 18000).
* tls.c - source code in C-language that via TCP connection reports and
  	      	logs real-time temperature measured by BBG temperature
		sensor(v1.2) and receives and processes TLS encrypted commands
		from the lever.cs.ucla.edu TLS server(port 19000).
* Makefile - contains targets: build(default), dist, and clean.  


Credits:
* Linux man pages online - http://man7.org/linux/man-pages/index.html
* OpenSSL Documentation - https://www.openssl.org/
* SSL Initialization Tutorial -
  https://wiki.openssl.org/index.php/SSL/TLS_Client#Initialization
* lever.cs.ucla.edu servers (TCP & TLS) -
  https://lasr.cs.ucla.edu/TCP_SERVER/index.html
  https://lasr.cs.ucla.edu/TLS_SERVER/index.html