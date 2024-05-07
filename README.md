# CSCE3560IDPSProject
Class Project for Detecting and Mitigating ICMP Ping Floods and SYN Floods CSCE 3560.001 Group 7

Attacks, Mitigation and Detection Programs were performed on an Ubuntu VM.
The IDPS contains two functions, syn_mitigation and icmp_mitigation, each of which tackles their respective attacks. syn_mitigation detects and blocks SYN requests for port 80 (it could work for any port) from an IP address if over 5 requests are received from that IP address. icmp_mitigation does the same as syn_mitigation, except for ICMP ping requests.

The mitigation system uses ufw, so make sure it is enabled (sudo ufw enable) and reset to defaults (sudo ufw reset).

Attacks:
SYN Flood: This python program sends 100 SYN packets to the specified ip address through the specified port.
ICMP Ping Flood: This shell program sends 100 ICMP Ping requests to the specified IP address.
