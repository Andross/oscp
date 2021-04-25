#!/bin/bash
host=10.3.3.34
for port in {1..65535}; do
timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
echo "port $port is open" | grep -v "No route to host" | grep -v "Connection refused"
done
echo "Done"