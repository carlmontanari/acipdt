FROM ubuntu:latest

MAINTAINER Tige Phillips <tige@tigelane.com>

RUN apt-get update
RUN apt-get -y upgrade

## Python
# RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-setuptools

## Python pip
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-pip
RUN DEBIAN_FRONTEND=noninteractive pip3 install --upgrade pip

## git
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install git

# acitool install
RUN DEBIAN_FRONTEND=noninteractive pip3 install git+https://github.com/carlniger/acitool

WORKDIR /root
RUN mkdir -p /root/acitool
COPY ./ /root/acitool/
WORKDIR /root/acitool/

RUN python3 setup.py install

# Drop users into root dir when running
WORKDIR /root/acitool
