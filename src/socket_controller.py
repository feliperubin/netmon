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


class SocketController:
	def __init__(self,iface):
		self.on = False
		self.__s = None
		self.__iface = iface
		try:
			self.__s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		except OSError as msg:
			# print('Error'+str(msg))
			print("Failed to create socket",self.__iface)
			exit(0)
		try:
			self.__s.bind((self.__iface,0))
		except OSError as msg:
			print("Failed to bind device",self.__iface)
			exit(0)


		# Get Device MAC Address
		
		self.mac = self.__s.getsockname()[4]
		# Get Device IP Address
		try:
			self.ip = fcntl.ioctl(self.__s.fileno(),SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24]
		except (OSError) as e:
			print("Failed to obtain IP Address of",self.__iface)
			exit(0)

		


		# Get Broadcast Address
		# SIOCSIFHWBROADCAST SIOCSIFBRDADDR

		# Get  Default Gateway
		# https://stackoverflow.com/questions/2761829/python-get-default-gateway-for-a-local-interface-ip-address-in-linux
		# Flags are RTF_* flags
		# /usr/include/linux/route.h
		try:
			with open("/proc/net/route") as route_f:
				for line in route_f:
					column = line.strip().split()
					if column[1] != '00000000' or not int(column[3], 16) & 2:
						continue
					else:
						# self.gw = socket.inet_ntoa(struct.pack("<L", int(column[2], 16)))
						self.gw = struct.pack("<L", int(column[2], 16))
						break
		except:
			print("Failed to obtain Gateway for",self.__iface)
			exit(0)
			
		print("Default Gateway: ",socket.inet_ntoa(self.gw))

		print("Raw Socket created on interface",self.__iface)
		
		# self.mac = utils.bytes2mac(self.__s.getsockname()[4])
		# self.ip = socket.inet_ntoa(fcntl.ioctl(self.__s.fileno(),SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])

	def sniffer(self,timeout=None): # Packet Sniffer
		if timeout is not None:
			self.__s.settimeout(timeout)
		self.on = True
		while self.on:
			yield self.__s.recvfrom(65536)
	
	def th_sniffer(self,q): # Packet Sniffer Thread
		self.on = True
		while self.on:
			p = self.__s.recvfrom(65536)
			q.put(p)

	
	# Sends a network packet
	# Send data to the socket. The socket must be connected to a remote socket
	def send(self,packet):
		self.__s.send(packet)


# socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
# Translate the host/port argument into a sequence of 5-tuples that contain all the necessary arguments for creating a socket connected to that service. host is a domain name, a string representation of an IPv4/v6 address or None. port is a string service name such as 'http', a numeric port number or None. By passing None as the value of host and port, you can pass NULL to the underlying C API.
# Convert an IPv4 address from dotted-quad string format (for example, ‘123.45.67.89’) to 32-bit packed binary format,
# socket.inet_aton

























