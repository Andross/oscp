#!/bin/bash
hosts=10.3.3.34,10.3.3.42,10.3.3.47,10.3.3.190,10.3.3.201
for host in $(echo $hosts | sed "s/,/ /g"); do
    echo "Scanning $host..."
    for port in {1..65535}; do
        timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
        echo "port $port is open" | grep -v "No route to host" | grep -v "Connection refused"
        time=$1

        # start the command in a subshell to avoid problem with pipes
        # (spawn accepts one command)
        command="bash -c \"echo >/dev/tcp/$host/$port\""

        expect -c "set echo \"-noecho\"; set timeout $time; spawn -noecho $command; expect timeout { exit 1 } eof { exit 0 }"    
        echo "? is $?"
        if [ $? = 1 ] ; then
            echo "Timeout after ${time} seconds"
        fi
    done

done
echo "Done"