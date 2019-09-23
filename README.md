# T2 Lab Redes


**Docker Execution**

```bash
# Build the container
docker build . -t netmon
# Run it
sudo docker run --rm -it -v $PWD/src:/src --privileged --network host netmon
```

SIGINT(2)
SIGKILL(9)


Test TCP Connection with curl
```bash
# Local Host
curl -vvv 192.168.15.35:3000
# Remote Host
curl -vvv https://cloud.fpbin.com
```

Ethernet
	|- ARP
	|- IP
		|-ICMP
		|-TCP
		|-UDP

Ethernet


**Python Stuff**
**Format**

IEEE 754 
'f', 'd' and 'e'  binary32, binary64 or binary16 regardless of the floating-point format used by the platform.


```bash
str[x:y]
(x:] , [y:) and (x:y)
```

```bash
socket.socket(socket.AF_PACKET, )
```
### Network Debugger

ETH_P_ALL = 0x0003


/usr/include/linux/


- Execute as root
