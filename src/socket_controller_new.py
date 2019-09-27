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
#http://man7.org/linux/man-pages/man7/netdevice.7.html

# Get IP Address of Interface
# Based on:
# https://stackoverflow.com/questions/27391167/struct-error-argument-for-s-must-be-a-bytes-object-in-python-3-4

# /usr/include/linux/ioctl.h
# /usr/include/asm-generic/ioctl.h

# ip - Linux IPv4 protocol implementation
# https://linux.die.net/man/7/ip

# Obtain Routes
# cat /proc/net/route
import fcntl

# Regarding Socket Types

# AF_INET Communication with TCP or UDP
# AF_INET6 IPv6
# AF_PACKET Used to receive and send raw packets on L2.

# socket.socket(domain,type,protocol)
#the domain (AF_PACKET for a packet socket);
#the socket type (SOCK_RAW if you want to capture the Ethernet headers or SOCK_DGRAM if not); and
#the protocol (equal to the required Ethertype, converted to network byte order), which is used for filtering inbound packets.

#https://docs.oracle.com/cd/E19455-01/806-1017/6jab5di2e/index.html
# AF_INET Internet family for IPv4 only 
# SOCK_STREAM, SOCK_DGRAM, or SOCK_RAW
# SOCK_STREAM : TCP
# SOCK_DGRAM : UDP
# SOCK_RAW : ICMP


# s = socket(family, type, protocol);
# If the protocol is unspecified (a value of 0),
# the system selects a protocol that supports 
#the requested socket type. 
#The socket handle (a file descriptor) is returned.


# Three types of sockets are supported:

# SOCK_STREAM
# Stream sockets allow processes to communicate using TCP. 
# A stream socket provides bidirectional, reliable, sequenced, 
# and unduplicated flow of data with no record boundaries. 
# After the connection has been established, data can be read 
# from and written to these sockets as a byte stream. 
# The socket type is SOCK_STREAM.

# SOCK_DGRAM
# Datagram sockets allow processes to use UDP to communicate. 
# A datagram socket supports bidirectional flow of messages. 
# A process on a datagram socket can receive messages in a 
# different order from the sending sequence and can receive 
# duplicate messages. Record boundaries in the data are preserved.
# The socket type is SOCK_DGRAM.

# SOCK_RAW
# Raw sockets provide access to ICMP. These sockets are normally
# datagram oriented, although their exact characteristics are 
# dependent on the interface provided by the protocol. 
# Raw sockets are not for most applications. They are provided to 
# support developing new communication protocols or for access to 
# more esoteric facilities of an existing protocol. Only superuser 
# processes can use raw sockets. The socket type is SOCK_RAW.

class SocketController:
	def __init__(self,iface,proto=None):

		self.on = False
		self.__s = None

		# self.gw = None
		self.mac = None
		self.ip = None
		self.__iface = iface
		self.proto = proto

		# #all
		# arp 
		# ____
		# icmp
		# tcp
		# udp

		# if self.proto == "icmp":
		# 	self.proto = socket.getprotobyname("icmp")
		# elif self.proto == "arp":
		# 	self.proto = 0
		# elif self.proto ==
		# socket.getprotobyname("icmp")
		# self.proto == 

		# Passive scan
		if self.proto is None:
			try:
				self.__s = socket.socket(\
					socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
			except:
				print("Failed to create Socket")
				exit(0)

			try:
				self.__s.bind((self.__iface,0))
			except:
				print("Failed to bind socket to",self.__iface)
				exit(0)
		
		elif self.proto == "arp":
			try:
				self.__s = socket.socket(\
					socket.AF_PACKET, socket.SOCK_RAW,0)
			except:
				print("Failed to create arp Socket")
				exit(0)
			try:
				self.__s.bind((self.__iface,0))
			except:
				print("Failed to bind socket to",self.__iface)
				exit(0)

		else:
			try:
				# self.__s = socket.socket(\
				# 	socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname(self.proto))					
				self.__s = socket.socket(\
					socket.AF_INET,socket.SOCK_RAW,0)				

			except OSError as err:
				print("Failed to create",self.proto,"Socket")
				print(err)
				exit(0)
			
			self.ip = socket.gethostbyname(socket.gethostname())
			self.__s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

			# self.mac = self.__s.getsockname()[4]
			print(self.__s.getsockname())



		# if self.__iface == '':
		# 	self.__iface = socket.gethostbyname(socket.gethostname())
		# 	self.ip = self.__iface

		# try: 
		# 	self.__s.bind((self.__iface,0))
		# except:
		# 	print("Failed to bind socket to",HOST)
		# self.mac = self.__s.getsockname()[4]

		# if self.ip is None:
		# 	self.ip = fcntl.ioctl(self.__s.fileno(),\
		# 		SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24]

	def sniffer(self,timeout=None): # Packet Sniffer
		self.on = True
		if timeout is not None:
			self.__s.settimeout(timeout)
		while self.on:
			yield self.__s.recvfrom(65536)
	
	# Threaded sniffer
	def th_sniffer(self,q): # Packet Sniffer Thread
		self.on = True
		while self.on:
			p = self.__s.recvfrom(65536)
			q.put(p)

	# Sends a network packet
	def send(self,packet):
		self.__s.send(packet)

		# if self.mode == 0:
		# 	try:
		# 		self.__s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		# 	except OSError as msg:
		# 		# print('Error'+str(msg))
		# 		print("Failed to create socket",self.__iface)
		# 		exit(0)
		# else:
		# 	return 0

		# if self.iface != '':
		# 	try:
		# 		self.__s.bind((self.__iface,0))
		# 	except OSError as msg:
		# 		print("Failed to bind to specified device",self.__iface)
		# 		exit(0)
		# else:
		# 	try:
		# 		self.ip = socket.gethostbyname(socket.gethostname())
		# 		s.bind((self.ip, 0))
		# 		self.__s.bind((self.__iface,0))
		# 	except OSError as msg:
		# 		print("Failed to bind")
		# 		exit(0)
				




		

	# def manual_creation():
	# 	# Get Device MAC Address
	# 	self.mac = self.__s.getsockname()[4]
	# 	# Get Device IP Address
	# 	try:
	# 		self.ip = fcntl.ioctl(self.__s.fileno(),SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24]
	# 	except (OSError) as e:
	# 		print("Failed to obtain IP Address of",self.__iface)
	# 		exit(0)

	# 	# Get  Default Gateway
	# 	# https://stackoverflow.com/questions/2761829/\
	# 	#python-get-default-gateway-for-a-local-interface-ip-address-in-linux
	# 	try:
	# 		with open("/proc/net/route") as route_f:
	# 			for line in route_f:
	# 				column = line.strip().split()
	# 				if column[1] != '00000000' or not int(column[3], 16) & 2:
	# 					continue
	# 				else:
	# 					# self.gw = socket.inet_ntoa(struct.pack("<L", int(column[2], 16)))
	# 					self.gw = struct.pack("<L", int(column[2], 16))
	# 					break
	# 	except:
	# 		print("Failed to obtain Gateway for",self.__iface)
	# 		exit(0)
			
	# 	print("Default Gateway: ",socket.inet_ntoa(self.gw))

	# 	print("Raw Socket created on interface",self.__iface)


		
		# self.mac = utils.bytes2mac(self.__s.getsockname()[4])
		# self.ip = socket.inet_ntoa(fcntl.ioctl(self.__s.fileno(),SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])




# socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
# Translate the host/port argument into a sequence of 5-tuples that 
# contain all the necessary arguments for creating a socket connected to 
# that service. host is a domain name, a string representation of an IPv4/v6 address
# or None. port is a string service name such as 'http', a numeric port number
# or None. By passing None as the value of host and port, you can pass NULL to 
# the underlying C API.
# Convert an IPv4 address from dotted-quad string format (for example, ‘123.45.67.89’)
# to 32-bit packed binary format,
# socket.inet_aton

























