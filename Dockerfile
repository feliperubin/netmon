FROM ubuntu:16.04
LABEL maintainer="Felipe Rubin"
LABEL version="1.0"
LABEL description="Network Monitor"

RUN apt-get update
RUN apt-get install -y python3 traceroute iproute2 iputils-ping net-tools
RUN apt-get install -y 
RUN apt-get install -y 
RUN apt-get install -y 
# Set python version
ENV PYTHON_VERSION=3.7.4
#ENV LANG=C.UTF-8
# ENTRYPOINT python3 /src/netmon.py
#WORKDIR /src/
# ENTRYPOINT ip link show

VOLUME /src
