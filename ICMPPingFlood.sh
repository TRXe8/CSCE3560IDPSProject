!/usr/bin/bash

ip.addr="192.168.63.132" #Change Target IP as required
max_pings=100
counter=0

while [ $count -lt $max_pings ]
do
    if [ping -c 1 $ip_addr >/dev/null];
    then
        echo "Ping Sent"
    else
        echo "Ping Failed"
    fi
    sleep 2
done
