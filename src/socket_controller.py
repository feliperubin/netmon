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
	def __init__(self,iface,proto=None):
		
		self.on = False
		self.__s = None
		self.__iface = iface
		self.proto = proto

		# self.__stype = "AF_PACKET"


		if proto is None:

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

			try: # First try
				self.mac = self.__s.getsockname()[4]
			except: # Second try
				try:
					with open("sys/class/net/"+self.__iface+"address") as addrf:
						self.mac = addrf.readline()
					self.mac = utils.mac2bytes(self.mac)
				except:
					print("Failed to obtain mac address for",self.__iface)
					exit(0)

		else:
			try:
				self.__s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.getprotobyname(proto))
				self.__s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
			except OSError as msg:
				# print('Error'+str(msg))
				print("Failed to create socket",self.__iface)
				exit(0)

		# Get Device IP Address
		try:
			self.ip = fcntl.ioctl(self.__s.fileno(),\
				SIOCGIFADDR,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24]
		except:
			try:
				self.ip = socket.gethostbyname(self.__s.gethostname())
			except:
				print("Failed to obtain IP Address of",self.__iface)
				exit(0)
		# Obtain the network mask
		try:
			self.netmask = socket.inet_ntoa(fcntl.ioctl(socket.socket(\
				socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])
			self.netmask = [int(x) for x in self.netmask.split('.')]
		except OSError as e:
			print("Failed to obtain Network Mask of",self.__iface)
			exit(0)

		if proto is None:
			print("Created Raw Socket iface ",self.__iface)
		else:
			print("Created Raw Socket iface ",self.__iface,"proto ",self.proto)
		
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

	# Send to a specific host
	def sendto(self,packet,dst,dstp=0):
		x = self.__s.sendto(packet,(dst,dstp))
		return x


