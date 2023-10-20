from dnslib import DNSRecord
import socket
import requests
import base64



def initialize(host,port):
    # Define the host and port to listen on
    
    # Create a socket to listen for incoming DNS requests
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))

    print(f"Listening for DNS requests on {host}:{port}")
    return server_socket

def messageFromDig(server_socket):
    data, ipaddress_port = server_socket.recvfrom(1024)
    # print(data)
    dns_request = DNSRecord.parse(data)
    
    print(f"Received DNS request from {ipaddress_port}\n")
    print("dig message request from out client+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++start\n")
    print(dns_request)
    print("dig message request from our client+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++end\n")
    return data,ipaddress_port

def binary_to_base64url(binary_data):
    # Encode the binary data to base64
    base64_encoded = base64.b64encode(binary_data).decode('utf-8')

    # Replace '+' with '-' and '/' with '_'
    base64url_encoded = base64_encoded.replace('+', '-').replace('/', '_')

    # Remove any padding '=' characters
    return base64url_encoded.rstrip('=')


def connectToServer(ipaddress,port,path,dnsmessage):
    # Define the IP address and port (if needed).
    ip_address = ipaddress  # Replace with the target IP address
    port = port  # Replace with the target port for HTTPS (usually 443)

    # Define the path or resource on the server.
    path = path  # Replace with the actual path or resource

    # Define the parameters you want to include in the request as a dictionary.
    params = {
        "method" :"GET",
        "accept" : "application/dns-message",
        "dns":binary_to_base64url(dnsmessage)
    }

    # Construct the full URL using the IP address, port, and path.
    url = f"https://{ip_address}:{port}{path}"

    # Send the GET request with the specified parameters.
    response = requests.get(url, params=params)  # Set 'verify' to False to ignore SSL certificate validation (for testing only)

    # Check if the request was successful (status code 200).
    if response.status_code == 200:
        # Print the response content (the content returned by the server).
        return response
    else:
        print(f"Request failed with status code {response.status_code}")
        return response
def communicateMessageBackToDig(server_socket,data,client_address):
    server_socket.sendto(data, client_address)
    
def main():
    print("hello world===============================================================")
    doh_server_address="1.1.1.1"
    server_socket=initialize('0.0.0.0',12345)
    while True:
        
        dns_request,ipaddress_port=messageFromDig(server_socket)
        response=connectToServer(doh_server_address,443,"/dns-query",dns_request)

        print("Response Content from doh server:===============================================================start")
        #print(response,"\n\n")
        #print(response.content)
        #print("\n\n")
        
        print(DNSRecord.parse(response.content))
        print("Response Content from doh server end:===============================================================end")
        communicateMessageBackToDig(server_socket,response.content,ipaddress_port)
        
    
if __name__ == "__main__":
    main()