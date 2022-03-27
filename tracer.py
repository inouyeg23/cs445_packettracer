import socket
import pyshark
import dns

time = input("Please enter a timeout value")

capture = pyshark.LiveRingCapture()
capture.sniff(timeout = time)

for packet in capture.sniff_continuously(packet_count=capture.size):
    print(packet.dns)


def checkSecure(url):
    if(url.find('https') != -1):
        print("secure webapge")
    else:
        print("non-secure")