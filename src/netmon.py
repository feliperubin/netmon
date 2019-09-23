#! /usr/bin/env python3
#
# netmon: Network Monitor
# Author: Felipe Pfeifer Rubin
# Contact: felipe.rubin@edu.pucrs.br
# About: Network Monitor for 
# PUCRS 2019/2 Course Computer Networks Lab

# Python has bugs...
# https://grokbase.com/t/python/python-bugs-list/
# 155s7p1fmf/issue24283-print-not-safe-in-signal-handlers

# https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
import signal
import sys
from monitor import Monitor
import time

banner = """
*********************
** Network Monitor **
*********************
"""

# monitor = None
# Handles the Signal Interrupt (SIGINT)
# and then properly exits
# def signal_handler(signal, frame):
def signal_handler():
	# monitor.stop()

	# while monitor.status():
	# 	continue

	b_repr = lambda x: str(round(x,2))+'B' if x < 1000 else kb_repr(x/1000)
	kb_repr = lambda x: str(round(x,2))+'KB' if x < 1000 else mb_repr(x/1000)
	mb_repr = lambda x: str(round(x,2))+'MB' if x < 1000 else gb_repr(x/1000)
	gb_repr = lambda x: str(round(x,2))+'GB'
	# TO DO: Test if amount is > 0
	stop_time = time.time()
	print("\n***************\n")  # New line 
	print("Metrics:")
	# Amount of packets per protocol
	# Implementation note: the 6 padding counts '.' as character
	if monitor.metrics['amount'] > 0:
		print("Protocol  Amount(%)  Packets")
		print("tcp        %6.2f     %d" % (100.0 * monitor.metrics['tcp']/monitor.metrics['amount'],monitor.metrics['tcp']))
		print("udp        %6.2f     %d" % (100.0 * monitor.metrics['udp']/monitor.metrics['amount'],monitor.metrics['udp']))
		print("arp        %6.2f     %d" % (100.0 * monitor.metrics['arp']/monitor.metrics['amount'],monitor.metrics['arp']))
		print("icmp       %6.2f     %d" % (100.0 * monitor.metrics['icmp']/monitor.metrics['amount'],monitor.metrics['icmp']))
		print("--------------------------------------------")
		print("Total      100.00     %d" % (monitor.metrics['amount']))
		print("Size: Max: %s  Min: %s"\
		 % (b_repr(monitor.metrics['max']),b_repr(monitor.metrics['min'])))
		print("--------------------------------------------")

		# Lambda Function to select value from dict item
		byvalue = lambda x: x[1]
		# Top 5 Big Senders
		bigsend = sorted(monitor.metrics['bigsend'].items(), key=byvalue, reverse=True)[:5]
		# Top 5 Big Receivers
		bigrecv = sorted(monitor.metrics['bigrecv'].items(), key=byvalue, reverse=True)[:5]
		# Top 5 Host Pair Talks
		talks = sorted(monitor.metrics['talks'].items(), key=byvalue, reverse=True)[:5]
		# Top 5 Overall Hosts Packet Size Count(send+recv)
		bigsize = sorted(monitor.metrics['bigsize'].items(), key=byvalue, reverse=True)[:5]

		print("Top    Senders       Packets")
		[print("%d    %-15s    %d" % (i+1,bigsend[i][0],bigsend[i][1])) for i in range(0,len(bigsend))]
		print("--------------------------------------------")
		print("\nTop    Receivers     Packets")
		[print("%d    %-15s    %d" % (i+1,bigrecv[i][0],bigrecv[i][1])) for i in range(0,len(bigrecv))]
		print("--------------------------------------------")
		print("Top      Host 1       Host 2      Exchanges")
		[print("%d  %-15s %-15s    %d" % (i+1,talks[i][0][0],talks[i][0][1],talks[i][1])) for i in range(0,len(talks))]
		print("--------------------------------------------")
		print("Top    Network       Utilization")
		[print("%d    %-15s    %s" % (i+1,bigsize[i][0],b_repr(bigsize[i][1]))) for i in range(0,len(bigsize))]
		print("--------------------------------------------")
	else:
		print("No packets were captured!")
	
	print("Network was monitored for: ",time.strftime("%H:%M:%S",time.gmtime(stop_time-start_time)))	
	sys.exit(0)

# Usage:
#   python3 netmon.py -i <iface> -p <port-port> -m <mode> 
def main():
	global monitor
	# start_time = 0
	global start_time
	# signal.signal(signal.SIGINT,signal_handler)
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
	start_time = time.time()
	monitor = Monitor(iface="eth2",mode=1,verbose=True,use_threads=True)
	
	try:
		monitor.start()
	except KeyboardInterrupt:
		signal_handler()


if __name__ == "__main__":
	main()











