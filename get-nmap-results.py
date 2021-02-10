#!/usr/bin/python3
import re

def findResults(fileName):
    with open(fileName) as fp:
        lines = fp.readlines()
        for line in lines:
            nmapLine = re.search('Nmap scan report for [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
            if(re.match('Nmap scan report for [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)):
                print(line.strip('\n'))

findResults('smb-discovery.txt')