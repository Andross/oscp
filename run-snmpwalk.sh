#!/bin/bash

ips=$1
mibs=(1.3.6.1.2.1.25.1.6.0 1.3.6.1.2.1.25.4.2.1.2 1.3.6.1.2.1.25.4.2.1.4 1.3.6.1.2.1.25.2.3.1.4 1.3.6.1.2.1.25.6.3.1.2 1.3.6.1.4.1.77.1.2.25 1.3.6.1.2.1.6.13.1.3)

for ip in $(cat $ips); 
do
	echo "Scanning $ip...";
	snmpwalk -c public -v1 -t 10 "$ip"; 
done
