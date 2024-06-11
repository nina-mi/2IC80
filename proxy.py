from netfilterqueue import NetfilterQueue
import os
import scapy.all as scapy

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

def proxy(packet):
    packet.accept() #allows to continue