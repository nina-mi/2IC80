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

#Whether this is a request from the server to switch to https
def https_switch_request(scapy_packet):
    #TODO
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

    if https_switch_request(scapy_packet):
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