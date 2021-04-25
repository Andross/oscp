import threading
import socket

#ip = socket.gethostbyname(target)

def portscan(port, host):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)# 
    #print("Scanning port %s" % port)
    try:
        con = s.connect((host,port))

        print('Port :',port,"is open.")

        con.close()
        return
    except: 
        pass
hosts = ['10.3.3.34','10.3.3.42','10.3.3.47','10.3.3.190','10.3.3.201']        
r = 1 

for host in hosts:
    maxThreads = False
    print('Scanning ' + str(host))
    for x in range(1,10000,1): 
        active = threading.active_count()
        #print('Thread count %s' %active)
        if active < 100:
            t = threading.Thread(target=portscan,kwargs={'port':x,'host':host})
            t.start() 
            t.join()
            r += 1
           
        