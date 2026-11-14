FROM redis:latest

RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install curl gcc make

ENV VERSION=0.0.6

WORKDIR /code
RUN curl -s -L -O "https://github.com/repsheet/redis_module/archive/${VERSION}.tar.gz"
RUN tar xzf ${VERSION}.tar.gz

WORKDIR /code/redis_module-${VERSION}
RUN make
RUN mkdir -p /lib
RUN cp src/repsheet.so /lib/

EXPOSE 6379

CMD ["redis-server", "--loadmodule", "/lib/repsheet.so"]
