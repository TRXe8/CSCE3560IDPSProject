#!/usr/bin/bash

ip_addr="192.168.63.132" #Change Target IP as required
max_pings=100
counter=0
echo "Starting ICMP Attack"

while [ $count -lt $max_pings ]
do
    if ping -c 1 $ip_addr >/dev/null;
    then
        if (( counter % 10 == 0 )); #prints every 10 packets
        then
            echo "$counter pings sent so far"
    else
        echo "Ping Failed"
    fi
    sleep 1 #Pause added to prevent overload of the system. Works completely fine w/o pause
done
echo "Completed ICMP Attack with $max_pings pings"
