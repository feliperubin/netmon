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
import time

# To stop waiting a packet that will never arrive.

class Scanner():
	def __init__(self,iface,netaddr,cidr,ports,verbose=False,use_threads=False):
		self.iface = iface
		self.on = False
		self.sc = SocketController(self.iface)
		self.icmp_sc = SocketController(self.iface,proto="icmp")
		self.tcp_sc = SocketController(self.iface,"tcp")
		self.udp_sc = SocketController(self.iface,"udp")
		
		# self.sc_arp = SocketController(self.iface,"arp")
		# self.sc_tcp = SocketController(self.iface,"tcp")
		# self.sc_udp = SocketController(self.iface,"udp")

		self.inspector = PacketInspector()
		self.creator = PacketCreator()
		# List of packets to wait. 
		# Ex: Send arp request, wait arp reply
		self.waiting_packet = {}
		
		self.ports = ports
		
		self.cache = {} # ip:mac
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

	def send_icmp_wait(self,ip_dst):
		# icmp_req_packet = self.creator.icmp_echo_request(
		# 	self.sc.ip,self.sc.mac,utils.dotted2bytes(ip_dst),\
		# 	utils.mac2bytes(mac_dst))

		icmp_req_packet = self.creator.icmp_echo_request(
			self.icmp_sc.ip,utils.dotted2bytes(ip_dst))

		# TA TIRANDO O ETHERNET...
		# This have a max time, if there's no answer or traffic it will stop.	
		# THIS HERE! MUST BE ON A THREAD ON A LIST WAITING TO GET ANSWER!!!
		dest_addr = socket.gethostbyname(ip_dst)
		self.icmp_sc.sendto(icmp_req_packet,dest_addr)
		start_time = time.time()
		for i in range(0,3):
			try:
				sniffer = self.sc.sniffer(timeout=1.5)
				raw_packet,address = next(sniffer)
				# print("HI RAW:",raw_packet)
				curr_time = time.time() # Current Time
				packet = self.inspector.process(raw_packet)
				# print(packet)
				# print("Raw Packet is: ",raw_packet,"And packet is:",packet)
				if packet is not None:
					if packet['eth']['type'] == 'ip':
						if packet['ip']['protocol'] == 'icmp':
							if packet['ip']['src'] == ip_dst and \
							packet['ip']['dst'] == utils.bytes2dotted(self.icmp_sc.ip):
								# return packet['eth']['src']
								return curr_time-start_time
			except socket.timeout:
				pass
		return None


	def send_icmp(self,ip_dst,dst_mac):
		return 0
	
	def same_network(self):
		# mask = 2**(32 - self.cidr)-1
		# Instead of testing with the host netmask, I will use mine
		for x,y,z in zip(struct.unpack("!BBBB",self.sc.ip),self.netaddr,self.sc.netmask):
			if x & z != y & z:
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
		# gw_ip = socket.inet_ntoa(self.sc.gw)
		# gw_mac = self.send_arp_wait(gw_ip)
		# if gw_mac is not None:
		# 	print("Obtained Gateway MAC Address")
		# else:
		# 	print("Failed to obtain the Gateway MAC Address.")
		# 	exit(0)

		for b0 in range(self.netaddr[0],self.netaddr[0]+256-self.netmask[0]):
			for b1 in range(self.netaddr[1],self.netaddr[1]+256-self.netmask[1]):
				for b2 in range(self.netaddr[2],self.netaddr[2]+256-self.netmask[2]):
					for b3 in range(self.netaddr[3],self.netaddr[3]+256-self.netmask[3]):
						host_ip = str(b0)+'.'+str(b1)+'.'+str(b2)+'.'+str(b3)
						# Actually, it's the gateway

						# I NEED TO USE THIS! socket.gethostbyname
						host_rtt = self.send_icmp_wait(host_ip)
						if host_rtt is not None:
							print("Host ",host_ip," rtt",host_rtt)
							self.cache[host_ip] = 0xFFFFFFFF
		return 0

	def network_discovery(self):
		if self.same_network():
			print("Same Network")
			self.arp_discovery()
		else:
			print("Different Network")
			self.icmp_discovery()
		return 0

	def tcp_scan_wait(self,ip_dst,dstp):
		tcp_syn_packet = self.creator.tcp_syn(
			self.tcp_sc.ip,80,utils.dotted2bytes(ip_dst),dstp)

		# This have a max time, if there's no answer or traffic it will stop.		
		dest_addr = socket.gethostbyname(ip_dst)
		self.tcp_sc.sendto(tcp_syn_packet,dest_addr,dstp)
		# start_time = time.time()
		# time.sleep(2)
		time.time()
		for i in range(0,5):
			try:
				# self.sc.send(tcp_syn_packet)
				sniffer = self.sc.sniffer(timeout=0.5)
				raw_packet,address = next(sniffer)
				# curr_time = time.time()
				packet = self.inspector.process(raw_packet)
				if packet is not None:
					# print(packet)
					if packet['eth']['type'] == 'ip':
						if packet['ip']['protocol'] == 'tcp':
							if packet['ip']['src'] == ip_dst:
								if packet['tcp']['dst'] == 80:
									if packet['ip']['dst'] == utils.bytes2dotted(self.sc.ip):
										if packet['tcp']['flag'] == 0x14:
											return False
										elif packet['tcp']['flag'] == 0x12:
											return True
										else:
											continue

							
					# if packet['eth']['type'] == 'ip':
					# 	if packet['ip']['protocol'] == 'tcp':
					# 		if packet['ip']['src'] == ip_dst and \
					# 		packet['ip']['dst'] == utils.bytes2dotted(self.sc.ip):

								# return curr_time-start_time
								# return packet['tcp']['src']
			except socket.timeout:
				pass
		return False

	def port_scan(self):
		my_port = 0
		# Must verify start_port <= end_port
		for host in self.cache:
			for pg in self.ports:
				for port in range(pg[0],pg[1]+1):
					# if self.tcp_scan_wait(host,self.cache[host],port):
					if self.tcp_scan_wait(host,port):
						print("Host %s has port %s/tcp open" % (host,port))
		# for 
		return 0

	# Begin Network Discovery
	def start(self):
		# print("Scanning Network %s.%s.%s.%s netmask %s.%s.%s.%s" % (self.netaddr,self.netmask))
		print("My IP: ",utils.bytes2dotted(self.sc.ip))
		print("My MAC: ",utils.bytes2mac(self.sc.mac))
		self.network_discovery()
		self.port_scan()
		self.on = True


		return 0




























