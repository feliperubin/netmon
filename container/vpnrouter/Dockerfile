FROM alpine:latest
LABEL maintainer="Felipe Rubin"
LABEL version="1.0"
LABEL description="OpenVPN Router"

# Install OpenVPN Client
RUN apk add openvpn
# Install tcpdump for debugging
RUN apk add tcpdump
## Required because of a bug 
## See https://github.com/moby/moby/issues/14140
RUN mv /usr/sbin/tcpdump /usr/local/bin/tcpdump 

# Copy bootstrap script to start tun interface
COPY bootstrap.sh /usr/local/bin/
RUN ln -s /usr/local/bin/bootstrap.sh /
# Not required for the moment. Allows packet forwarding
# RUN sysctl net.ipv4.conf.all.forwarding=1 

# Environment variable in case container interface is not eth0
# ENV NW="eth0"

# Add iptable rules and start the client connection
ENTRYPOINT \
echo -e "######VPN Router######\n$(ip addr show eth0 |\
grep 'inet\s*' | awk '{print $2}' | cut -f1 -d '/')\n######################\n" ;\
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT ; \
iptables -A FORWARD -i tun0 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT ;\
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE ; \
/usr/sbin/openvpn --config /config/*.ovpn

# Volume with the client.ovpn file.
# to mount it use -v file_path:/config
# e.g. $PWD:/config
VOLUME /config

# Host(docker:172.17.0.1) --> (172.17.0.2:eth0)Container(tun0:10.8.1.2) --> (tun0:server)
