#! /usr/bin/env python3
#
# netmon: Network Monitor
# Author: Felipe Pfeifer Rubin
# Contact: felipe.rubin@edu.pucrs.br
# About: Network Monitor for 
# PUCRS 2019/2 Course Computer Networks Lab


# https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
import signal
import sys
from monitor import Monitor

banner = """
*********************
** Network Monitor **
*********************
"""

# monitor = None
# Handles the Signal Interrupt (SIGINT)
# and then properly exits
def signal_handler(signal, frame):
	# TO DO: Test if amount is > 0
	print("\n***************\n")  # New line 
	print("Metrics:")
	# Amount of packets per protocol
	# Implementation note: the 6 padding counts '.' as character
	if monitor.metrics['amount'] > 0:
		print("Protocol  Amount(%)  Packets")
		print("tcp        %6.2f      %d" % (100.0 * monitor.metrics['tcp']/monitor.metrics['amount'],monitor.metrics['tcp']))
		print("udp        %6.2f      %d" % (100.0 * monitor.metrics['udp']/monitor.metrics['amount'],monitor.metrics['udp']))
		print("arp        %6.2f      %d" % (100.0 * monitor.metrics['arp']/monitor.metrics['amount'],monitor.metrics['arp']))
		print("icmp       %6.2f      %d" % (100.0 * monitor.metrics['icmp']/monitor.metrics['amount'],monitor.metrics['icmp']))
		print("-------------------------------")
		print("Total      100.00     ",monitor.metrics['amount'])
		print("Size(B): Max: %d  Min: %d"\
		 % (monitor.metrics['max'],monitor.metrics['min']))

	else:
		print("No packets were captured!")

	sys.exit(0)

# Usage:
#   python3 netmon.py -i <iface> -p <port-port> -m <mode> 
def main():
	global monitor
	signal.signal(signal.SIGINT,signal_handler)
	# try:
	# 	iface = None
	# 	ports = (None,None)
	# 	mode = 0
	# 	for i in range (1,len(sys.argv[1:])):
	# 		if sys.argv[i] == "-i":
	# 			iface = sys.argv[i+1]
	# 		elif sys.argv[i] == "-p":
	# 			ports[0] = sys.argv[i+1],sys.argv[i+2]
	# 		elif sys.argv[i] == "-m":
	# 			mode = sys.argv[i+1]
	# 		else:
	# 			continue
	# except:
	# 	print("netmon:Unrecognized Parameters\nUsage:\
	# 		python3 netmon.py -i <iface> -p <port-port> -m <mode>")
	# 	exit(0)
	print(banner)
	monitor = Monitor(iface="eth2",mode=0,verbose=True)
	monitor.start()



if __name__ == "__main__":
	main()











