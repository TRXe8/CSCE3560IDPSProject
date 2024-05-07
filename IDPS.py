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
                if ICMP_IP_ADDR[src_ip] > 5:
                    #if ICMP_IP_ADDR[src_ip] = 6:
                    
                    #print(f"Blocking ICMP Request from {src_ip}")
                    #    os.system("sudo ufw deny 80/tcp from src_ip")
                    #else:
                        print (f"ICMP request from {src_ip} blocked")
                        return
        send(packet)
    sniff(filter="icmp", prn=icmp_mitigation)  
p1 = multiprocessing.Process(target=icmpMit)

p1.start()

p1.join()
