

# import threading
# import Queue

# Mode: Passive 0 ,  Active 1
# Raw Buffer: Receives Raw Packages to filter later
# Packet Data: Packets that were stored
# Packet Metrics: Metrics regarding the obtained packets
#
# metrics:
#  host:
#
#


import time
from socket_controller import SocketController
from packet_inspector import PacketInspector
class Monitor():
	def __init__(self,iface,mode,verbose=False):
		self.mode = mode
		self.verbose = verbose
		self.raw_buffer = []
		self.packet_data = []
		self.metrics = {'amount':0,'tcp':0,'udp':0,\
		'icmp':0,'arp':0,'bigsend':{},'bigrecv':{},'min':65536,'max':0}

		self.iface = iface
		self.sc = None
		self.on = 0
		self.inspector = PacketInspector()
	# Set Network Interface
	def set_iface(self,iface):
		if self.on:
			print("Monitor must be powered off")
			return
		self.iface = iface
	# Set Monitoring Mode	
	def set_mode(self,mode):
		if self.on:
			print("Monitor must be powered off")
			return
		self.mode = mode
	def pretty_print(self,dpacket,padding="",incr=" "):
		for key,value in dpacket.items():
			
			if type(value) is dict:
				print(padding+str(key)+":")
				self.pretty_print(value,padding+incr)
			else:
				print(padding+str(key)+": "+str(value))
				# print(padding+str(value))
	# Start Monitoring
	def start(self): # Starts Monitoring
		self.sc = SocketController(self.iface)
		self.on = 1
		sniffer = self.sc.sniffer()
		while self.on:
			raw_packet,address = next(sniffer)
			# print("Address: ",address)

			packet = self.inspector.process(raw_packet)

			if packet is not None:
				self.packet_data.append(packet)
				self.metrics['amount']+=1
				proto = packet['eth']['type']
				src_ip = ''
				dst_ip = ''
				if proto == 'ip':
					proto = packet['ip']['protocol']
					src_ip = packet['ip']['src']
					dst_ip = packet['ip']['dst']
				else:
					src_ip = packet['arp']['src']['ip']
					dst_ip = packet['arp']['dst']['ip']

				if src_ip in self.metrics['bigsend']:
					self.metrics['bigsend'][src_ip]+= 1
				else:
					self.metrics['bigsend'][src_ip] = 1
				if dst_ip in self.metrics['bigrecv']:
					self.metrics['bigrecv'][dst_ip]+= 1
				else:
					self.metrics['bigrecv'][dst_ip] = 1

				self.metrics[proto]+=1
				lenp = len(raw_packet)
				if lenp < self.metrics['min']:
					self.metrics['min'] = lenp
				if lenp > self.metrics['max']:
					self.metrics['max'] = lenp


				if self.verbose:
					print("***************")
					self.pretty_print(packet," ","  ")
					# print("Packet: ",packet)

	# Stop Monitoring
	def stop(self):
		self.on = 0
		self.sc = None
		return 0



















		
