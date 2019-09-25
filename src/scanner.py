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
class Scanner():
	def __init__(self,iface,netaddr,cidr,ports,verbose=False,use_threads=False):
		self.iface = iface
		self.on = False
		self.sc = SocketController(self.iface)
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
		
	def send_icmp(self,dst_ip,dst_mac):
		return 0
	
	def same_network(self):
		# mask = 2**(32 - self.cidr)-1
		for x,y,z in zip(struct.unpack("!BBBB",self.sc.ip),self.netaddr,self.netmask):
			if x & z != y:
				return False
		return True
	# Begin Network Discovery
	def start(self):
		print("Same Network: ",self.same_network())
		# self.send_arp("192.168.15.153")
		self.on = True
		# start_ip = [x&y for x,y in zip(self.netaddr,utils.cidr2mask(cidr)

		for b0 in range(self.netaddr[0],self.netaddr[0]+256-self.netmask[0]):
			for b1 in range(self.netaddr[1],self.netaddr[1]+256-self.netmask[1]):
				for b2 in range(self.netaddr[2],self.netaddr[2]+256-self.netmask[2]):
					for b3 in range(self.netaddr[3],self.netaddr[3]+256-self.netmask[3]):
						host = struct.pack("!BBBB",b0,b1,b2,b3)
						print("IP: %d.%d.%d.%d" % (b0,b1,b2,b3))
		return 0



# /*Test if inet2 ip is on the same subnet of inet1*/
# // int same_subnet(struct inet inet1, struct inet inet2)
# int same_subnet(struct inet inet1, uint32_t ip2)
# {
# 	uint32_t first_addr=inet1.ip&(0xFFFFFFFF << (32 - inet1.prefix));
# 	uint32_t last_addr=first_addr|(0xFFFFFFFF >> (inet1.prefix));
# 	return ip2 >= first_addr && ip2 <= last_addr;
# }


# for b3 in range(ip[3],mask[3]):
# 	for b2 in range(ip[2],mask[2]):
# 		for b1 in range(ip[1],mask[1]):
# 			for b0 in range(ip[0],mask[0]):
# 				host = struct.pack("!BBBB",b3,b2,b1,b0)


# mask = [0,0,0,0]
# octet = self.cidr
# for i in range(0,4):
# 	mask[i] = 255
# 	if octet < 8:
# 		mask[i] = mask[i] >> (8-octet)
# 		break
# 	octet-=8		

# for b0 in range(self.netaddr[0],self.netaddr[0]+256-self.netmask[0]):
# 	for b1 in range(self.netaddr[1],self.netaddr[1]+256-self.netmask[1]):
# 		for b2 in range(self.netaddr[2],self.netaddr[2]+256-self.netmask[2]):
# 			for b3 in range(self.netaddr[3],self.netaddr[3]+256-self.netmask[3]):
# 				host = struct.pack("!BBBB",b0,b1,b2,b3)
# 				print("IP: %d.%d.%d.%d" % (b0,b1,b2,b3))












