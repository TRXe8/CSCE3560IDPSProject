import multiprocessing, psutil, os
from scapy.all import *

def icmpMit():
    ICMP_IP_ADDR = {}
    def icmp_mitigation(packet):
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src

            if src_ip not in ICMP_IP_ADDR:
                ICMP_IP_ADDR[src_ip] = 1
            else:
                ICMP_PACKET_COUNT[src_ip] += 1
                if ICMP_IP_ADDR[src_ip] > 5:
                    print ("Blocking ICMP request from {src_ip}")
                    return
        send(packet)
    sniff(filter="icmp", prn=icmp_mitigation)  
p1 = multiprocessing.Process(target=icmpMit)

p1.start()

p1.join()
