for /L %i in (1,1,255) do @ping -n 1 -w 200 10.1.1.%i > nul &&
echo 10.1.1.%i is up.