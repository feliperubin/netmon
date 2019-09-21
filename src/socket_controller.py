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
import queue
ETH_P_ALL = 0x0003 # Every Packet

class SocketController:
	def __init__(self,iface):
		self.on = False
		self.__s = None
		self.__iface = iface
		try:
		    self.__s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		except OSError as msg:
		    print('Error'+str(msg))
		    sys.exit(1)
		self.__s.bind((self.__iface,0))
		print('Socket created on interface',self.__iface)		

	def sniffer(self): # Packet Sniffer
		self.on = True
		while self.on:
			yield self.__s.recvfrom(65536)
	
	def th_sniffer(self,q): # Packet Sniffer Thread
		self.on = True
		while self.on:
			p = self.__s.recvfrom(65536)
			q.put(p)

