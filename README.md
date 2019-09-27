# T2 Lab Redes

Aluno: Felipe Pfeifer Rubin
Mat: 15105085-3

**Execução**
```bash

```


**Code Execution**
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
# Build the container
docker build . -t netmon
# Run it
sudo docker run --rm -it -v $PWD/src:/src --privileged --network host netmon
```

**Vagrantfile**
```bash
vagrant up
```
