FROM ubuntu:20.04

LABEL name=fuzzable
LABEL src="https://github.com/ex0dus-0x/fuzzable"

ENV LANG C.UTF-8

RUN apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-dev python3-pip git wget
RUN python3 -m pip install -U pip

ADD . /fuzzable
RUN cd /fuzzable && python3 -m pip install .

CMD ["/bin/bash"]
