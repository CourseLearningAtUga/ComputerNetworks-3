from dnslib import DNSRecord

# Binary DNS data received as bytes (replace this with your actual data)
binary_data = b'\x86\x06\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x03www\x06google\x03com\x00\x00\x1c\x00\x01\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\x9a\xe5\x951\x90\t}\x8f'

# Parse the binary DNS data
dns_record = DNSRecord.parse(binary_data)

# Access the questions in the DNS record
questions = dns_record.questions

# Check if there are questions (usually there is only one in a query)
if questions:
    question = questions[0]  # Assuming there's only one question

    # Get the record type and domain from the question
    record_type = question.qtype
    domain = question.qname

    print("Record Type:", record_type)
    print("Domain:", domain)
else:
    print("No questions in the DNS record.")
