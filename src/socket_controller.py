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


# See netdevice(7)
SIOCGIFADDR=0x8915 # Get/Set a device's address.


# Get IP Address of Interface
# Based on:
# https://stackoverflow.com/questions/27391167/struct-error-argument-for-s-must-be-a-bytes-object-in-python-3-4

# /usr/include/linux/ioctl.h
# /usr/include/asm-generic/ioctl.h


import fcntl


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


		# Get Device MAC Address
		self.mac = utils.bytes2mac(self.__s.getsockname()[4])
		
		# Get Device IP Address
		self.ip = socket.inet_ntoa(fcntl.ioctl(self.__s.fileno(),SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])

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

























