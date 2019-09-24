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
class Scanner():
	def __init__(self,iface,net,cidr,ports,verbose=False,use_threads=False):
		self.iface = iface
		self.on = False
		self.sc = SocketController(self.iface)
		# List of packets to wait. 
		# Ex: Send arp request, wait arp reply
		self.waiting_packet = {}
		self.net = net
		self.cidr = cidr
		self.ports = ports
		# self.monitor = Monitor()
		# self.sc = monitor.sc
		# ip:mac
		self.cache = {}

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

	def each_ip(self):
		mask = 32 - self.cidr
		

	def same_network(self):
		return True
	# Begin Network Discovery
	def start(self):
		self.send_arp("192.168.15.153")
		self.on = True
		return 0
























