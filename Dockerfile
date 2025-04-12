FROM docker.io/alpine:3.21 AS build

RUN apk add --no-cache make gcc musl-dev cmake libmicrohttpd-dev ruby

COPY . /app
WORKDIR /app

RUN cd thirdparty/prometheus-client-c && \
	cmake -B build -S prom && \
	make -C build && \
	make -C build install

RUN make test dht

FROM docker.io/alpine:3.21
RUN apk add --no-cache libmicrohttpd
COPY --from=build /usr/local/lib/libprom.so /usr/lib/libprom.so

COPY --from=build /app/dht /app/dht

VOLUME /data
EXPOSE 6981
WORKDIR /data

ENTRYPOINT /app/dht
