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
                    
                    #    print(f"Blocking ICMP Request from {src_ip}")
                    #    os.system("sudo ufw deny icmp from src_ip")
                    #else:
                        print (f"ICMP request from {src_ip} blocked")
                        return
        send(packet)
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
                if SYN_IP_ADDR[src_ip] > 5:
                    #if SYN_IP_ADDR[src_ip] = 6:
                        #print (f"Blocking ICMP Request from {src_ip}")
                        #os.system("sudo ufw deny 80/tcp from src_ip")
                    #else:
                    print (f"SYN Request from {src_ip} blocked")
                    return
        send(packet)
    sniff(filter="tcp", prn = syn_mitigation)
            
p1 = multiprocessing.Process(target=icmpMit)
p2 = multiprocessing.Process(target=synMit)

p1.start()
p2.start()

p1.join()
p2.join()
