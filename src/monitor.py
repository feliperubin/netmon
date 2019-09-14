

# import threading
# import Queue

# Mode: Passive 0 ,  Active 1
# Raw Buffer: Receives Raw Packages to filter later
# Packet Data: Packets that were stored
# Packet Metrics: Metrics regarding the obtained packets
from socket_controller import SocketController
class Monitor():
	def __init__(self,iface,mode):
		self.mode = mode
		self.raw_buffer = []
		self.packet_data = {}
		self.packet_metrics = {}
		self.iface = iface
		# self.sc = SocketController()
		self.sc = None
		self.on = 0
	# Set Network Interface
	def set_iface(self,iface):
		if self.on:
			print("Monitor must be powered off")
			return
		self.iface = iface
	# Set Monitoring Mode	
	def self_mode(self,mode):
		if self.on:
			print("Monitor must be powered off")
			return
		self.mode = mode
	# Start Monitoring
	def start(self): # Starts Monitoring
		self.sc = SocketController(self.iface)
		self.on = 1
		while self.on:
			self.sc.next()

	# Stop Monitoring
	def stop(self):
		self.on = 0
		self.sc = None
		return 0


		
