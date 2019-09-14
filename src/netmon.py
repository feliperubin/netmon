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


# Handles the Signal Interrupt (SIGINT)
# and then properly exits
def signal_handler(signal, frame):
	global metrics
	print("") # New line 
	print("Metrics here")
	sys.exit(0)

# Usage:
#   python3 netmon.py -i <iface> -p <port-port> -m <mode> 
def main():
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
	monitor = Monitor(iface="eth2",mode=0)
	monitor.start()


if __name__ == "__main__":
	main()











