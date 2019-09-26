#
#
# Network Scanner
#
#
from socket_controller import SocketController
from packet_inspector import PacketInspector
from packet_creator import PacketCreator
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
		self.creator = PacketCreator()
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




	# Sends ARP Request Packet and Wait an answer until a chosen timeout
	def send_arp_wait(self,ip_dst):

		arp_req_packet = self.creator.arp_request(self.sc.ip,self.sc.mac,ip_dst)

		# This have a max time, if there's no answer or traffic it will stop.		
		for i in range(0,3):
			try:
				self.sc.send(arp_req_packet)
				sniffer = self.sc.sniffer(timeout=0.5)
				raw_packet,address = next(sniffer)
				packet = self.inspector.process(raw_packet)

				if packet is not None:
					if packet['eth']['type'] == 'arp':
						if packet['arp']['src']['ip'] == ip_dst and \
						packet['arp']['dst']['mac'] == utils.bytes2mac(self.sc.mac):
							return packet['arp']['src']['mac']
			except socket.timeout:
				pass
		return None

	def send_icmp_wait(self,ip_dst,mac_dst):
		icmp_req_packet = self.creator.icmp_echo_request(
			self.sc.ip,self.sc.mac,utils.dotted2bytes(ip_dst),\
			utils.mac2bytes(mac_dst))

		# This have a max time, if there's no answer or traffic it will stop.		
		for i in range(0,3):
			try:
				self.sc.send(icmp_req_packet)
				sniffer = self.sc.sniffer(timeout=1.5)
				raw_packet,address = next(sniffer)
				packet = self.inspector.process(raw_packet)
				if packet is not None:
					if packet['eth']['type'] == 'ip':
						if packet['ip']['protocol'] == 'icmp':
							if packet['ip']['src'] == ip_dst and \
							packet['ip']['dst'] == utils.bytes2dotted(self.sc.ip):
								return packet['eth']['src']
			except socket.timeout:
				pass
		return None


	def send_icmp(self,ip_dst,dst_mac):
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
						host_ip = str(b0)+'.'+str(b1)+'.'+str(b2)+'.'+str(b3)
						host_mac = self.send_arp_wait(host_ip)
						if host_mac is not None:
							print("Host %s (%s)" % (host_ip,host_mac))
							self.cache[host_ip] = host_mac


	def icmp_discovery(self):
		gw_ip = socket.inet_ntoa(self.sc.gw)
		gw_mac = self.send_arp_wait(gw_ip)
		if gw_mac is not None:
			print("Obtained Gateway MAC Address")
		else:
			print("Failed to obtain the Gateway MAC Address.")
			return 0

		for b0 in range(self.netaddr[0],self.netaddr[0]+256-self.netmask[0]):
			for b1 in range(self.netaddr[1],self.netaddr[1]+256-self.netmask[1]):
				for b2 in range(self.netaddr[2],self.netaddr[2]+256-self.netmask[2]):
					for b3 in range(self.netaddr[3],self.netaddr[3]+256-self.netmask[3]):
						host_ip = str(b0)+'.'+str(b1)+'.'+str(b2)+'.'+str(b3)
						# Actually, it's the gateway
						host_mac = self.send_icmp_wait(host_ip,gw_mac)
						if host_mac is not None:
							print("Host ",host_ip)
							self.cache[host_ip] = host_mac
		return 0

	def network_discovery(self):
		if self.same_network():
			print("Same Network")
			self.arp_discovery()
		else:
			print("Different Network")
			self.icmp_discovery()
		return 0

	# Begin Network Discovery
	def start(self):
		# print("Scanning Network %s.%s.%s.%s netmask %s.%s.%s.%s" % (self.netaddr,self.netmask))
		self.network_discovery()
		# if self.same_network():
		# 	print("Same Network")
		# 	self.local_discovery()
		# else:
		# 	print("Different Network")
		# 	self.network_discovery()
		# 	# Get Default Gateway MAC Address
		# 	gw_ip = socket.inet_ntoa(self.sc.gw)
		# 	gw_mac = self.send_arp_wait(gw_ip)
		# 	if gw_mac is not None:
		# 		print("Got Gateway MAC!")
		# 		icmp_result = self.send_icmp_wait('8.8.8.8',gw_mac)	
		# 		if icmp_result:
		# 			print("Host",gw_ip)
		# 	else:
		# 		print("Failed to get Gateway MAC!")
		# 		exit(0)
		# self.send_arp("192.168.15.153")
		self.on = True
		# start_ip = [x&y for x,y in zip(self.netaddr,utils.cidr2mask(cidr)

		print('Final Cache:')
		for i in self.cache:
			print("Host %s (%s)" % (i,self.cache[i]))
		return 0












