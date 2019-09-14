#
#
#
#
# iface: Network Interface, e.g. eth0, enp4s0
#
import socket,sys
import struct
import os
import time
ETH_P_ALL = 0x0003 # Every Packet
class SocketController:
	def __init__(self,iface):
		self.s = None
		self.iface = iface
		try:
		    self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		except OSError as msg:
		    print('Error'+str(msg))
		    sys.exit(1)
		self.s.bind((self.iface,0))
		print('Socket created on interface',self.iface)		

	def next(self): # Reads next packet
		while True:
			yield self.s.recvfrom(65536)

