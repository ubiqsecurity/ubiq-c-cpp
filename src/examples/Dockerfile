FROM debian:bullseye

RUN apt-get -y update

COPY build/*.deb /tmp/
RUN apt -y install /tmp/*.deb && rm -f /tmp/*.deb

COPY build/src/examples/ubiq_sample-* /usr/bin/
COPY build/src/examples/ubiq_sample_fpe-* /usr/bin/
