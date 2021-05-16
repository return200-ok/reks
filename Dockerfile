FROM ubuntu:18.04
RUN apt update && \
    apt-get upgrade -y \
    apt-get install build-essential \
    apt install manpages-dev \
    apt install libpcap-dev \
    apt install libnet-dev 
#note libnet v1.1.0
# libpcap v0.7.1
