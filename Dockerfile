FROM python:latest
LABEL maintainer="Felipe Rubin"
LABEL version="1.0"
LABEL description="Network Monitor"

# Set python version
ENV PYTHON_VERSION=3.7.4
ENV LANG=C.UTF-8
# ENTRYPOINT python3 /src/netmon.py
WORKDIR /src/
# ENTRYPOINT ip link show

VOLUME /src
