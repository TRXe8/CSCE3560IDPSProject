import multiprocessing, os
from scapy.all import *

def icmpMit():
    ICMP_IP_ADDR = {}
    def icmp_mitigation(packet):
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src

            if src_ip not in ICMP_IP_ADDR:
                ICMP_IP_ADDR[src_ip] = 1
            else:
                ICMP_IP_ADDR[src_ip] += 1
                if ICMP_IP_ADDR[src_ip] == 6:
                    print(f"Blocking ICMP Requests from {src_ip}")
                    result = os.system(f"sudo ufw deny proto icmp from {src_ip}")
                    blocked = 0
                    if result == 0:
                        print(f"Successfully blocked {src_ip}")
                    else
                        print(f"Error blocking {src_ip}")
                elif ICMP_IP_ADDR[src_ip] > 6:
                    blocked += 1
                    if blocked % 10 == 0:
                        print(f"ICMP requests from {src_ip} have been blocked {blocked} times")

    sniff(filter="icmp", prn=icmp_mitigation)

def synMit():
    SYN_IP_ADDR = {}
    def syn_mitigation(packet):
        if packet.haslayer(TCP) and packet[TCP].flags & 2 and packet.haslayer(IP):
            src_ip = packet[IP].src
        
            if src_ip not in SYN_IP_ADDR:
                SYN_IP_ADDR[src_ip] = 1
            else:
                SYN_IP_ADDR[src_ip] += 1
                if SYN_IP_ADDR[src_ip] == 6:
                    print(f"Blocking SYN requests from {src_ip}")
                    result = os.system(f"sudo ufw deny proto 80/tcp from {src_ip}")
                    blocked = 0
                    if result == 0:
                        print(f"Successfully blocked {src_ip}")
                    else
                        print(f"Error blocking {src_ip}")
                elif SYN_IP_ADDR[src_ip] > 6:
                    blocked += 1
                    if blocked % 10 == 0:
                        print(f"SYN Requests from {src_ip} have been blocked {blocked} times")

    sniff(filter="tcp", prn = syn_mitigation)
            
p1 = multiprocessing.Process(target=icmpMit)
p2 = multiprocessing.Process(target=synMit)

p1.start()
p2.start()

p1.join()
p2.join()
