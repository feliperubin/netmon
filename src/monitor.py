

# import threading
# import Queue

# Mode: Passive 0 ,  Active 1
# Raw Buffer: Receives Raw Packages to filter later
# Packet Data: Packets that were stored
# Packet Metrics: Metrics regarding the obtained packets
from socket_controller import SocketController
from packet_inspector import PacketInspector
class Monitor():
	def __init__(self,iface,mode):
		self.mode = mode
		self.raw_buffer = []
		self.packet_data = {}
		self.packet_metrics = {}
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
				print(padding+str(key))
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

				self.pretty_print(packet," ","  ")
				# print("Packet: ",packet)

	# Stop Monitoring
	def stop(self):
		self.on = 0
		self.sc = None
		return 0



















		
