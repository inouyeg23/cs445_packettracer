import socket
import pyshark
import dns

print("Beginning capture: \n")

capture = pyshark.LiveCapture(interface="en0",only_summaries=False, display_filter='dns')
#capture.set_debug()
capture.sniff(timeout=20)

for packet in capture.sniff_continuously(packet_count=5):
    print(packet)
