import socket
import pyshark
import dns


#number of packets in a span of time vary depending on how many sites visited
#also, can't manually input timeout, since capture ends on packet_count
#num_packets = int(input("How many packets would you like to track? "))

blacklist = ["google.com", "apple.com", "azure.com", "microsoft.com"]

print("Beginning capture: \n")

capture = pyshark.LiveCapture(interface="en0",only_summaries=False, display_filter='dns')
#capture.set_debug()
capture.sniff(timeout=10, packet_count=15)

for packet in capture.sniff_continuously(packet_count=15):
    dns_name = packet.dns.qry_name
    for name in blacklist:
        if name in dns_name:
            dns_name = dns_name + " <---- blacklisted"
    print(dns_name)
