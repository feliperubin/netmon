# T2 Lab Redes

**Code Execution**
```bash
# Scan -s
python3 netmon.py -s -i eth0 -p 5000-5001 -n 192.168.15.10/32
python3 netmon.py -s -i eth0 -p 80 -n 192.168.15.0/24
# Monitor
python3 netmon.py -m -i eth0
```


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

[1,2,3,4,5,6,7,8][1:] = [2,3,4,5,6,7,8]  #here is a slice from index 1 until end
[1,2,3,4,5,6,7,8][2:4] = [3,4]    # [x,y] -> [ x; y-1] , same as for
[1,2,3,4,5,6,7,8][:2] = [1,2]    # here is from the start until before index(2)

```

```bash
socket.socket(socket.AF_PACKET, )
```
### Network Debugger

ETH_P_ALL = 0x0003


/usr/include/linux/


- Execute as root
