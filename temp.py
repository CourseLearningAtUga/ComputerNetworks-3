import dns.message
import dns.rcode
from dns import query

# Your DNS query in string format
query_string = "example.com IN A"

# Parse the DNS query from the string
parsed_query = dns.message.from_text(query_string)

# Create a DNS response message with an NXDOMAIN response code (RCODE 3) for the query
response = dns.message.make_response(parsed_query)
response.set_rcode(dns.rcode.NXDOMAIN)

# Set the ID (16-bit identifier)
response.id = parsed_query.id

# Print the NXDOMAIN response
print(response)
