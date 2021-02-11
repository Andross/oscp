#!/usr/bin/python3
import re
import sys

def findResults(fileName):
    f = open("results.txt", "w")
    with open(fileName) as fp:
        nmapResults = []
        lines = fp.readlines()
        matchFound = False
        pipeFound = False
        for line in lines:
            if(matchFound == True and not re.match('Nmap scan report for [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)):
                nmapResults.append(line)
            # nmapLine = re.search('Nmap scan report for [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
            if(re.match('Nmap scan report for [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line) and matchFound == False):
                nmapResults.append(line)
                matchFound = True
                #print(matchFound)
            elif(re.match('Nmap scan report for [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line) and matchFound == True):
                #print('here')
                    # print('{0} and pipe is {1}'.format(nmapResults,pipeFound))
                writeResults(f, nmapResults)
                matchFound = False
                pipeFound = False
                nmapResults = []

        f.close()

def writeResults(f, nmapResults):
    pipeFound = False
    for line in nmapResults:
        if '|' in line:
            pipeFound = True
            #print('Pipe found in {0}'.format(line))
            break
    if pipeFound == True:    
        for line in nmapResults:
            f.write(line)

if(len(sys.argv) < 2):
    print('File expected for parsing. Run with ./get-nmap-results.py nmap-results.txt')
    exit(0)

findResults(sys.argv[1])