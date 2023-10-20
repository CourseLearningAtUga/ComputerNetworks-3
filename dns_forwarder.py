from dnslib import DNSRecord,QTYPE
import socket
import requests
import base64
from scapy.all import DNS, DNSQR, IP, UDP, Ether, sendp,DNSRR
import dns.message
import dns.rcode



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
    print(dns_request,"\n\n")
    # print(dns_request.questions)
    print("dig message request from our client+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++end\n")
    return data,ipaddress_port,dns_request.questions,dns_request.questions[0].qname,dns_request.questions[0].qtype

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


def presentInDenyList(dnsmessage,denylist):
    print("deny list is ====",denylist)
    for x in denylist:
        # print(x)
        if x==dnsmessage:
            return True
    return False

def convert_to_nxdomain(response_data):
    try:
        # Parse the DNS response data
        response = dns.message.from_wire(response_data)

        # Create an NXDOMAIN response
        nxdomain_response = dns.message.make_response(response)

        # Set the response code to NXDOMAIN (RCODE 3)
        nxdomain_response.set_rcode(dns.rcode.NXDOMAIN)

        # Remove any answer records, authority records, and additional records
        nxdomain_response.answer = []
        nxdomain_response.authority = []
        nxdomain_response.additional = []

        # Return the NXDOMAIN response in binary format
        return nxdomain_response.to_wire()

    except dns.exception.DNSException as e:
        print(f"Error converting to NXDOMAIN: {e}")
        return None
   # !!!!!!!!!!!!!!!!!!!!!! code assumes there is only one question per dig
def main():
    print("hello world===============================================================")
    doh_server_address="8.8.8.8"
    doh_port=443
    denylist_filename="deny_list.txt"
    querylog_filename="queries.log"
    server_socket=initialize('0.0.0.0',12345)
    denylist=[]
    with open(denylist_filename, 'r') as file:
    # Read each line from the file and split it into a list of strings
        for line in file:
            denylist.append(line.strip())
    while True:
        dns_request,ipaddress_port,dns_request_message,dns_request_question,dns_request_question_type=messageFromDig(server_socket)
        requestedDnsRequestInDenyList=presentInDenyList(dns_request_question,denylist)
        if requestedDnsRequestInDenyList:
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            print(dns_request_question," in denylist\n")
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            nxdomain_response_data=convert_to_nxdomain(dns_request)
            communicateMessageBackToDig(server_socket,nxdomain_response_data,ipaddress_port)#since UDP protocol cannot say if it was sent
            with open(querylog_filename, 'a+') as file:
                file.write(f"{dns_request_question} {QTYPE[dns_request_question_type]} DENY\n")
        else:
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            print(dns_request_question,"not in denylist\n")
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            response=connectToServer(doh_server_address,doh_port,"/dns-query",dns_request)
            print("Response Content from doh server:===============================================================start")
            #print(response,"\n\n")
            #print(response.content)
            #print("\n\n")
            print(DNSRecord.parse(response.content))
            print("Response Content from doh server end:===============================================================end")
            communicateMessageBackToDig(server_socket,response.content,ipaddress_port)#since UDP protocol cannot say if it was sent
            with open(querylog_filename, 'a+') as file:
                file.write(f"{dns_request_question} {QTYPE[dns_request_question_type]} ALLOW\n")
        
    
if __name__ == "__main__":
    main()