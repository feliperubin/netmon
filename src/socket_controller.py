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
import utils
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
		self.mac = self.__s.getsockname()[4]

	def sniffer(self): # Packet Sniffer
		self.on = True
		while self.on:
			yield self.__s.recvfrom(65536)
	
	def th_sniffer(self,q): # Packet Sniffer Thread
		self.on = True
		while self.on:
			p = self.__s.recvfrom(65536)
			q.put(p)


# socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
# Translate the host/port argument into a sequence of 5-tuples that contain all the necessary arguments for creating a socket connected to that service. host is a domain name, a string representation of an IPv4/v6 address or None. port is a string service name such as 'http', a numeric port number or None. By passing None as the value of host and port, you can pass NULL to the underlying C API.
# Convert an IPv4 address from dotted-quad string format (for example, ‘123.45.67.89’) to 32-bit packed binary format,
# socket.inet_aton












