
**Build**
```bash
docker build . -t vpnrouter
```

**Run**
```bash
# Normal
sudo docker run -it -v $PWD:/config --privileged vpnrouter
# Detach Mode
sudo docker run -it -d -v $PWD:/config --privileged vpnrouter
```

### Considerations
Docker will only execute bootstrap.sh if run with `--privileged`, it won't work if it runs with `--cap-add=NET_ADMIN`.

