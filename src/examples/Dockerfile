FROM debian:stable

RUN apt-get -y update &&                        \
    apt-get -y install                          \
            libcurl4                            \
            libssl1.1

COPY build/*.deb /tmp/
RUN apt -y install /tmp/*.deb && rm -f /tmp/*.deb

COPY build/src/examples/ubiq_sample-* /usr/bin/
