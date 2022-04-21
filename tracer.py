import socket
import pyshark
import dns


#number of packets in a span of time vary depending on how many sites visited
#also, can't manually input timeout, since capture ends on packet_count
#num_packets = int(input("How many packets would you like to track? "))

#our list of blacklisted sites; can add more to array
blacklist = ["google.com", "apple.com", "azure.com", "microsoft.com"]

print("Beginning capture: \n")

#begin live capture
#parameters: 
#interface -> en0 represents wifi
#display_filter -> set to 'dns' to only display dns info
capture = pyshark.LiveCapture(interface="en0", display_filter='dns')
#capture.set_debug()

#set live capture sniffing parameters
capture.sniff(timeout=10, packet_count=15)

#print up to 15 packets per capture
for packet in capture.sniff_continuously(packet_count=15):
    dns_name = packet.dns.qry_name
    #flag if packet dns query name matches a name in the blacklist
    for name in blacklist:
        if name in dns_name:
            dns_name = dns_name + " <---- blacklisted"
    print(dns_name)
