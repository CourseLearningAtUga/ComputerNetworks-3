#!/usr/bin/env python3
from dnslib import DNSRecord, QTYPE
import argparse
import socket
import requests
import base64
import dns.message
import dns.rcode

def initialize(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"Listening for DNS requests on {host}:{port}")
    return server_socket

def messageFromDig(server_socket):
    data, ipaddress_port = server_socket.recvfrom(1024)
    dns_request = DNSRecord.parse(data)
    print(f"Received DNS request from {ipaddress_port}\n")
    print("dig message request from our client +++++++++++++++++++++++++++++++ start\n")
    print(dns_request, "\n\n")
    print("dig message request from our client +++++++++++++++++++++++++++++++ end\n")
    return data, ipaddress_port, dns_request.questions, dns_request.questions[0].qname, dns_request.questions[0].qtype

def binary_to_base64url(binary_data):
    base64_encoded = base64.b64encode(binary_data).decode('utf-8')
    base64url_encoded = base64_encoded.replace('+', '-').replace('/', '_')

    return base64url_encoded.rstrip('=')
def connectToDnsServer(ip_address,port, dnsmessage):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(dnsmessage, (ip_address, port))
        response, _ = sock.recvfrom(1024)  
        return response
    except socket.error as e:
        print(f'Error: {e}')
        return response
    finally:
        sock.close()

def connectToDohServer(ip_address, port, path, dnsmessage):
    params = {
        "method": "GET",
        "accept": "application/dns-message",
        "dns": binary_to_base64url(dnsmessage)
    }
    url = f"https://{ip_address}:{port}{path}"
    response = requests.get(url, params=params) 
    
    if response.status_code == 200:
        return response
    else:
        print(f"Request failed with status code {response.status_code}")
        return response

def communicateMessageBackToDig(server_socket, data, client_address):
    server_socket.sendto(data, client_address)

def presentInDenyList(dnsmessage, denylist):
    print("deny list is ====", denylist)
    for x in denylist:
        if x == dnsmessage:
            return True
    return False

def convert_to_nxdomain(response_data):
    try:
        response = dns.message.from_wire(response_data)
        nxdomain_response = dns.message.make_response(response)
        nxdomain_response.set_rcode(dns.rcode.NXDOMAIN)
        nxdomain_response.answer = []
        nxdomain_response.authority = []
        nxdomain_response.additional = []
        return nxdomain_response.to_wire()

    except dns.exception.DNSException as e:
        print(f"Error converting to NXDOMAIN: {e}")
        return None

def main(args):
    if not (args.doh or args.DOH_SERVER or args.DST_IP):
        print("Error: You must use -d if neither --doh nor --doh_server are specified.")
        return

    if args.doh:
        doh_server_address = "8.8.8.8"
    else:
        doh_server_address = str(args.DOH_SERVER)
        
    doh_port = 443
    denylist_filename = args.DENY_LIST_FILE
    querylog_filename = args.LOG_FILE
    dns_server=args.DST_IP
    dns_port=53

    if args.doh and args.DOH_SERVER:
        print("Error: Cannot use --doh and --doh_server together.")
        return
        
    server_socket = initialize('0.0.0.0', 53)
    denylist = []
    
    with open(denylist_filename, 'r') as file:
        for line in file:
            denylist.append(line.strip())
    while True:
        dns_request, ipaddress_port, dns_request_message, dns_request_question, dns_request_question_type = messageFromDig(server_socket)
        requestedDnsRequestInDenyList = presentInDenyList(dns_request_question, denylist)
        if requestedDnsRequestInDenyList:
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
                print(dns_request_question, " in denylist\n")
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
                nxdomain_response_data = convert_to_nxdomain(dns_request)
                communicateMessageBackToDig(server_socket, nxdomain_response_data, ipaddress_port)  # since UDP protocol cannot say if it was sent
                if querylog_filename:
                    with open(querylog_filename, 'a+') as file:
                        file.write(f"{dns_request_question} {QTYPE[dns_request_question_type]} DENY\n")
        else:
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            print(dns_request_question, " not in denylist\n")
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
            if dns_server:
                response=connectToDnsServer(dns_server,dns_port, dns_request)
                print("Response Content from DNS server: ======================================================================================================== start")
                print("Response Content from DNS server: ======================================================================================================== start")
                print(DNSRecord.parse(response))
                print("Response Content from DNS server: ========================================================================================================== end")
                print("Response Content from DNS server: ========================================================================================================== end")
                communicateMessageBackToDig(server_socket, response, ipaddress_port)
            else:
                response = connectToDohServer(doh_server_address, doh_port, "/dns-query", dns_request)
                print("Response Content from doh server: ========================================================================================================= start")
                print(DNSRecord.parse(response.content))
                print("Response Content from doh server: =========================================================================================================== end")
                print("Response Content from doh server: =========================================================================================================== end")
                communicateMessageBackToDig(server_socket, response.content, ipaddress_port)  # since UDP protocol cannot say if it was sent
            if querylog_filename:
                with open(querylog_filename, 'a+') as file:
                    file.write(f"{dns_request_question} {QTYPE[dns_request_question_type]} ALLOW\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="DST_IP", help="Destination DNS server IP")
    parser.add_argument("-f", dest="DENY_LIST_FILE", help="File containing domains to block", required = True)
    parser.add_argument("-l", dest="LOG_FILE", help="Log file for query results")
    parser.add_argument("--doh", action="store_true", help="Use default upstream DoH server")
    parser.add_argument("--doh_server", dest="DOH_SERVER", help="Use this upstream DoH server")
    args = parser.parse_args()
    main(args)
