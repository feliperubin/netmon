# T2 Lab Redes

Author: Felipe Pfeifer Rubin
Contact: felipe.rubin@edu.pucrs.br

About: A python 3 implementation of a network scanning tool
with similar capabilities as nmap. There exists two modes, one
for passive monitoring (i.e. sniffing) and another for active scanning.

**Metrics**
- Overall quantity monitored packets.
- Percentage of packets by protocol.
- Min and Max sizes of all packets.
- Top 5 IP Addreses that sent the most packets.
- Top 5 IP Addreses that received the most packets.
- \*Top 5 pairs of IP Addresses that exchanged the most packets.
- \*Top 5 IP Addresses that participated (sending and receiving) in
the overall volume on packet data on the network.


**Execution**
```bash
python3 netmon.py <-s|-m> -i <iface> -p <port|port-port> -n <net/cidr>
Execution might require superuser (sudo) permission.
Parameters:
-h : Print this help
-s : Active Scan Mode
-m : Passive Monitoring Mode
-p : Either a port or a port range (port-port)
-i : Network Interface (e.g. eth0)
-n : Network Address/CIDR
```

**Samples**
```bash
# Scan -s
python3 netmon.py -s -i eth0 -p 5000-5001 -n 192.168.15.10/32
python3 netmon.py -s -i eth0 -p 80 -n 192.168.15.0/24 
sudo python3 netmon.py -s -i eth2 -p 22 -n 201.54.139.56/24
# Monitor
python3 netmon.py -m -i eth0
```

**Docker**
```bash
# Creates an ubuntu container environment with python3 and other network utilities.
# Build the container
docker build . -t netmon
# Run it (it will be destroyed when exited) 
sudo docker run --rm -it -v $PWD/src:/src --privileged --network host netmon
# Navigate to /src and execute the default commands.
```

**Vagrantfile**
```bash
# Creates an Ubuntu 16.04 Virtual Machine with 3 network interfaces.
# A default one, another for public networking and the last for private networking without the interference of 
# By default the following providers are supported: VMware Desktop, VMware Fusion Pro, Parallels Desktop and VirtualBox.
vagrant up 
```

