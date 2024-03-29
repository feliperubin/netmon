
# Raw Buffer: Receives Raw Packages to filter later
# Packet Data: Packets that were stored
# Packet Metrics: Metrics regarding the obtained packets
#
# Additional metrics:
# Bandwidth
#
#


import time
from socket_controller import SocketController
from packet_inspector import PacketInspector
import threading
import queue

class Monitor():
	def __init__(self,iface,verbose=False,use_threads=False):
		self.verbose = verbose
		# self.raw_buffer = []
		self.packet_data = []
		self.metrics = {'amount':0,'tcp':0,'udp':0,\
		'icmp':0,'arp':0,'bigsend':{},'bigrecv':{},\
		'min':65536,'max':0,\
		'talks':{},'bigsize':{}}

		self.iface = iface
		self.sc = SocketController(self.iface)
		self.on = 0
		self.inspector = PacketInspector()
		self.raw_buffer = queue.Queue(maxsize=0)
		self.use_threads = use_threads
		
	def pretty_print(self,dpacket,padding="",incr=" "):
		for key,value in dpacket.items():
			
			if type(value) is dict:
				print(padding+str(key)+":")
				self.pretty_print(value,padding+incr)
			else:
				print(padding+str(key)+": "+str(value))
	def ordered_print(self,p,padding="",incr=" "):
		print("[eth src:%s dst:%s type:%s]" % (p['eth']['src'],p['eth']['dst'],p['eth']['type']))
		if p['eth']['type'] == "ip":
			print("[ip src:%s dst:%s proto:%s ttl:%d]" % (p['ip']['src'],p['ip']['dst'],p['ip']['protocol'],p['ip']['ttl']))
			if p['ip']['protocol'] == "icmp":
				px = p['icmp']
				if px['type'] == 0 or px['type'] == 8:
					print("[icmp type:%s id:%d sequence:%d payload:%s]" % (px['name'],px['id'],px['sequence'],px['payload']))
				else:
					print("[icmp type:%s]",px['name'])
			else:
				px = p[p['ip']['protocol']]
				print("["+p['ip']['protocol']+" src:%d dst:%d]" % (px['src'],px['dst'])) 
		else:
			s = 'response'
			if p['arp']['op'] == 1:
				s = 'request'
			print("[arp %s src:(mac:%s,ip:%s)\ndst:(mac:%s,ip:%s) op:%s]" % (
				s,
			 	p['arp']['src']['mac'],p['arp']['src']['ip'],
			 	p['arp']['dst']['mac'],p['arp']['dst']['ip'],
			 	p['arp']['op']))
	

	def start_sniffer(self):
		while self.on:
			self.raw_buffer.put(next(sniffer))
		return 0
	
	# True if it's on, False otherwise.
	def status(self):

		return self.on == 1 or self._start_on == 1

	# Start Monitoring
	def start(self): # Starts Monitoring
		self._start_on = 1
		self.on = 1
		sniffer = None
		if self.use_threads:
			worker = threading.Thread(target=self.sc.th_sniffer,args=(self.raw_buffer,))
			worker.setDaemon(True)
			worker.start()
		else:
			sniffer = self.sc.sniffer()
		# raw_packet,address = None,None

		while self.on:
			packet = None
			if self.use_threads:
				raw_packet,address = self.raw_buffer.get()
				packet = self.inspector.process(raw_packet)
			else:
				raw_packet,address = next(sniffer)
				packet = self.inspector.process(raw_packet)

			# packet = self.inspector.process(raw_packet)

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
					self.metrics['bigsend'][src_ip]= 1
				if dst_ip in self.metrics['bigrecv']:
					self.metrics['bigrecv'][dst_ip]+= 1
				else:
					self.metrics['bigrecv'][dst_ip]= 1

				self.metrics[proto]+=1
				lenp = len(raw_packet)
				if lenp < self.metrics['min']:
					self.metrics['min']= lenp
				if lenp > self.metrics['max']:
					self.metrics['max']= lenp

				talk_key = (src_ip,dst_ip)
				if src_ip < dst_ip:
					talk_key = (dst_ip,src_ip)
				if talk_key in self.metrics['talks']:
					self.metrics['talks'][talk_key] += 1
				else:
					self.metrics['talks'][talk_key] = 1

				if src_ip not in self.metrics['bigsize']:
					self.metrics['bigsize'][src_ip] = lenp
				else:
					self.metrics['bigsize'][src_ip] += lenp
				if dst_ip not in self.metrics['bigsize']:
					self.metrics['bigsize'][dst_ip] = lenp
				else:
					self.metrics['bigsize'][dst_ip] += lenp


				if self.verbose:
					print("*************************")
					# self.pretty_print(packet," ","  ")
					self.ordered_print(packet)
					# print(self.compact_print(packet,"",""))
					# print("Packet: ",packet)
			else:
				pass
		self._start_on = 0
		# self.sc = None
		# print("Not on anymore!")
	
	# Stop Monitoring
	def stop(self):
		self.on = 0
		return 0

