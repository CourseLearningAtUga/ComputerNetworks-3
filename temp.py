from dnslib import DNSRecord
dns_response_data = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\xd8\xef\x25\x01'
dns_record = DNSRecord.parse(dns_response_data)
question = dns_record.q
domain = question.qname
print(f"Question: {question.qname} ({question.q.qtype})")
print(f"Domain: {domain}")
