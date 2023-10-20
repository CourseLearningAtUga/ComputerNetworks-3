from dnslib import DNSRecord
import socket

def initialize(host,port):
    # Define the host and port to listen on
    
    # Create a socket to listen for incoming DNS requests
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))

    print(f"Listening for DNS requests on {host}:{port}")
    return server_socket

def messageFromDig(server_socket):
    data, ipaddress_port = server_socket.recvfrom(1024)
    dns_request = DNSRecord.parse(data)
    print(f"Received DNS request from {ipaddress_port}:\n\n\n\n\n{dns_request}")
    return dns_request
    


    
def main():
    print("hello world")
    doh_server_address="1.1.1.1"
    server_socket=initialize('0.0.0.0',12345)
    while True:
        
        dns_request=messageFromDig(server_socket)
        print("\n\n")
        # print(dns_request)
        
    
if __name__ == "__main__":
    main()