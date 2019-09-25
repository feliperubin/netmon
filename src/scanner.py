#
#
# Network Scanner
#
#
from socket_controller import SocketController
from packet_inspector import PacketInspector
import threading
import queue
import struct 
import socket
import utils


# To stop waiting a packet that will never arrive.

class Scanner():
	def __init__(self,iface,netaddr,cidr,ports,verbose=False,use_threads=False):
		self.iface = iface
		self.on = False
		self.sc = SocketController(self.iface)
		self.inspector = PacketInspector()
		# List of packets to wait. 
		# Ex: Send arp request, wait arp reply
		self.waiting_packet = {}
		
		self.ports = ports
		# self.monitor = Monitor()
		# self.sc = monitor.sc
		# ip:mac
		self.cache = {}
		self.cidr = cidr
		# Octet array representation: /24 is [255,255,255,0]
		self.netmask = utils.cidr2mask(cidr)

		# Just to make sure.
		self.netaddr = [x & y for x,y in zip(netaddr,self.netmask)]




	# Sends ARP Request Packet
	def send_arp(self,dst_ip):
		
		# MAC Origem - 6 bytes
		# source_mac = b"\xa4\x1f\x72\xf5\x90\x41"
		protocol = 0x0806
		# Header Ethernet
		# MAC Destino - 6 bytes
		dst_mac = b"\xff\xff\xff\xff\xff\xff"
		eth_hdr = struct.pack("!6s6sH", dst_mac, self.sc.mac, protocol)

		# Header ARP
		htype = 0x1
		ptype = 0x0800
		hlen = 0x6
		plen = 0x4
		op = 0x1 # request
		dst_mac = b"\x00\x00\x00\x00\x00\x00"
		arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype,\
		 hlen, plen, op, self.sc.mac, self.sc.ip, dst_mac,socket.inet_aton(dst_ip))

		packet = eth_hdr+arp_hdr		
		self.sc.send(packet)

	def send_arp_wait(self,dst_ip):
		
		# MAC Origem - 6 bytes
		# source_mac = b"\xa4\x1f\x72\xf5\x90\x41"
		protocol = 0x0806
		# Header Ethernet
		# MAC Destino - 6 bytes
		dst_mac = b"\xff\xff\xff\xff\xff\xff"
		eth_hdr = struct.pack("!6s6sH", dst_mac, self.sc.mac, protocol)

		# Header ARP
		htype = 0x1
		ptype = 0x0800
		hlen = 0x6
		plen = 0x4
		op = 0x1 # request
		dst_mac = b"\x00\x00\x00\x00\x00\x00"
		arp_hdr = struct.pack("!HHBBH6s4s6s4s", htype, ptype,\
		 hlen, plen, op, self.sc.mac, self.sc.ip, dst_mac,socket.inet_aton(dst_ip))

		arp_req_packet = eth_hdr+arp_hdr		
		
		
		# for i in range(0,3):

		# This have a max time, if there's no answer or traffic it will stop.
		
		for i in range(0,3):
			try:
				self.sc.send(arp_req_packet)
				sniffer = self.sc.sniffer(timeout=0.1)
				raw_packet,address = next(sniffer)
				packet = self.inspector.process(raw_packet)

				if packet is not None:
					if packet['eth']['type'] == 'arp':
						if packet['arp']['src']['ip'] == dst_ip and \
						packet['arp']['dst']['mac'] == utils.bytes2mac(self.sc.mac):
							return packet['arp']['src']['mac']
			except socket.timeout:
				pass
		return None



	def send_icmp(self,dst_ip,dst_mac):
		return 0
	
	def same_network(self):
		# mask = 2**(32 - self.cidr)-1
		for x,y,z in zip(struct.unpack("!BBBB",self.sc.ip),self.netaddr,self.netmask):
			if x & z != y:
				return False
		return True

	# Send arp request for each ip address on the network
	# when an arp reply is received, insert the ip:mac on the arp cache.
	def arp_discovery(self):
		for b0 in range(self.netaddr[0],self.netaddr[0]+256-self.netmask[0]):
			for b1 in range(self.netaddr[1],self.netaddr[1]+256-self.netmask[1]):
				for b2 in range(self.netaddr[2],self.netaddr[2]+256-self.netmask[2]):
					for b3 in range(self.netaddr[3],self.netaddr[3]+256-self.netmask[3]):
						# host = struct.pack("!BBBB",b0,b1,b2,b3)
						host_ip = str(b0)+'.'+str(b1)+'.'+str(b2)+'.'+str(b3)
						for i in range(0,2):
							host_mac = self.send_arp_wait(host_ip)
							if host_mac is not None:
								print("Host %d.%d.%d.%d (%s)" % (b0,b1,b2,b3,host_mac))
								self.cache[host_ip] = host_mac
								break;

	# Begin Network Discovery
	def start(self):
		# print("Scanning Network %s.%s.%s.%s netmask %s.%s.%s.%s" % (self.netaddr,self.netmask))

		if self.same_network():
			print("Same Network")
			self.arp_discovery()
			
		else:
			print("Different Network")
		print("Same Network: ",self.same_network())
		# self.send_arp("192.168.15.153")
		self.on = True
		# start_ip = [x&y for x,y in zip(self.netaddr,utils.cidr2mask(cidr)

		print('Final Cache:')
		for i in self.cache:
			print("Host %s (%s)" % (i,self.cache[i]))
		return 0












