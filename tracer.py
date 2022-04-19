import socket
import pyshark
import dns


#number of packets in a span of time vary depending on how many sites visited
#also, can't manually input timeout, since capture ends on packet_count
num_packets = int(input("How many packets would you like to track? "))


print("Beginning capture: \n")

capture = pyshark.LiveCapture(interface="en0",only_summaries=False, display_filter='dns')
#capture.set_debug()
capture.sniff(timeout=10, packet_count=num_packets)

for packet in capture.sniff_continuously(packet_count=num_packets):
    #printing code from: https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info
    try:
        if packet.dns.qry_name:
            print ('DNS Request from %s: %s' % (packet.ip.src, packet.dns.qry_name))
    except AttributeError as e:
        #ignore packets that aren't DNS Request
        pass
    try:
        if packet.dns.resp_name:
            print ('DNS Response from %s: %s' % (packet.ip.src, packet.dns.resp_name))
    except AttributeError as e:
        #ignore packets that aren't DNS Response
        pass
