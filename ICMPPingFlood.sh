!/usr/bin/bash

ip.addr="" #Change Target IP as required
max_pings=100
counter=0

while [ $count -lt $max_pings ]
do
    if [ping -c1 $ip_addr >/dev/null];
    then
        echo "Ping Sent"
    else
        echo "Ping Failed"
    fi
    sleep 2
done
