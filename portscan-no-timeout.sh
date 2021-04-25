#!/bin/bash
hosts=127.0.0.1,10.3.3.34,10.3.3.42,10.3.3.47,10.3.3.190,10.3.3.201
for host in $(echo $hosts | sed "s/,/ /g"); do
    echo "Scanning $host..."
    for port in {8080..8080}; do
        time=1

        # start the command in a subshell to avoid problem with pipes
        # (spawn accepts one command)
        command="echo >/dev/tcp/$host/$port"
        
        expect -c "set echo \"-noecho\"; set timeout $time; spawn -noecho $command &&
echo \"port $port is open\" | grep -v \"No route to host\" | grep -v \"Connection refused\"; expect timeout { exit 1 } eof { exit 0 }" 
        echo $command
        
    done

done
echo "Done"