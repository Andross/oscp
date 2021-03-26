#!/usr/bin/python3

import socket
import sys

if len(sys.argv) != 3:
    print("Usage: vrfy.py <file-with-usernames> <file-with-ips>")
    sys.exit(0)

def enum_users(userFile, ipFile):
    with open(userFile, 'r') as uf:
        with open(ipFile, 'r') as ipf:
            usernames = uf.readlines()
            ips = ipf.readlines()
            for ip in ips:
                #create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print('Connecting to ip: {0}'.format(ip))
                #connect to server
                connect = s.connect(('10.11.1.229',25))
                #receive banner
                banner = s.recv(1024)
                #print banner
                print(banner)
                for user in usernames:
                    #verify a user
                    command = b'VRFY ' + user.encode('utf-8') + b'\r\n'
                    print('Sending command: {0}'.format(command))
                    s.send(command)
                    result = s.recv(1024)
                    print(result)
                s.close()
            
enum_users(sys.argv[1],sys.argv[2])
