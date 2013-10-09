#! /usr/bin/env python
from scapy.all import *
from random import randint

# Create the skeleton of our packet
template = IP(dst="172.16.20.10")/TCP()

# Start lighting up those bits!
template[TCP].flags = "UFP"

# Create an array with a large number of packets to send
# Each packet will have a random TCP dest port for attack obfuscation
xmas = []
for pktNum in range(0,100):
	xmas.extend(template)
	xmas[pktNum][TCP].dport = randint(1,65535)

# Send the array of packets
send(xmas)