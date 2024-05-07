# CSCE3560IDPSProject
Class Project for Detecting and Mitigating ICMP Ping Floods and SYN Floods CSCE 3560.001 Group 7

Attacks, Mitigation and Detection Programs were performed on an Ubuntu VM.
The IDPS contains two functions, syn_mitigation and icmp_mitigation, each of which tackles their respective attacks. syn_mitigation detects and blocks SYN requests for port 80 (it could work for any port) from an IP address if over 5 requests are received from that IP address. icmp_mitigation does the same as syn_mitigation, except for ICMP ping requests. A ufw rule is created whenever an IP address passes the threshold of 5 requests of either SYN or ICMP (sudo ufw deny proto $protocol from $ipAddress), which should mitigate the remainder of the attack.

Dependencies: The mitigation system adds ufw rules as part of its procedures, so make sure it is enabled (sudo ufw enable) and reset to defaults (sudo ufw reset).
Usage: sudo python3 IDPS.py

Attacks:
SYN Flood: This python program sends 100 SYN packets to the specified ip address through the specified port.
ICMP Ping Flood: This shell program sends 100 ICMP Ping requests to the specified IP address.

Usage for ICMPPingFlood: 
chmod +x ICMPPingFlood.sh
./ICMPPingFlood.sh

Usage for SYNFlood:
sudo python3 SYNFlood.py

Joint Dependencies: Both the SYN Flood and the IDPS use the scapy library, so it needs to be installed on both attacker and target systems (sudo apt-get install python3-scapy). The scapy library requires admin privileges, so the associated programs need to be run in sudo.
