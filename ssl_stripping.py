import netfilterqueue
import scapy.all as scapy

#https://venafi.com/blog/what-are-ssl-stripping-attacks/
#Typical sequence of events
#1. user reaches out to server with http
#2. server sends response requesting to use https instead
#3. user initiates https connection

#SSL stripping attack
# we want to intercept 2., then initiate https ourselves, and send http to the user


#TODO method for keeping track of ssl stripped sessions/victim-server pairs/idk?

#Check whether this is a redirect to https
def https_switching_request(scapy_packet):
    if scapy_packet.haslayer(scapy.HTTPResponse):
        http_layer = scapy_packet.getlayer(scapy.HTTPResponse)
        if http_layer.Location.contains('https://'):
            if http_layer.Status_Code[0] == "3": #3xx status code is for redirection (wikipedia)
                return True
    return False

# client <--http--> us <--https--> server
def existing_connection(scapy_packet):
    #TODO
    return False

def to_server(scapy_packet):
    #TODO
    return False


#alternative proxy method to just dns spoofing
def proxy_just_ssl(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if https_switching_request(scapy_packet):
        print("a")
        #TODO transform to packet without switching request and send to client

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