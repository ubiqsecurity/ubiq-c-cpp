FROM debian:stable

RUN apt-get -y update &&                        \
    apt-get -y upgrade &&                       \
    apt-get -y install                          \
    cmake                                       \
    dpkg-dev                                    \
    file                                        \
    g++                                         \
    libcurl4-openssl-dev                        \
    libssl-dev

COPY . /src
WORKDIR /src

RUN mkdir build &&                              \
    cmake -S. -Bbuild &&                        \
    make -Cbuild -j$(nproc) package
