FROM registry.hub.docker.com/library/alpine:3.22 AS build

RUN apk add --no-cache curl-dev libcurl make gcc musl-dev cmake libmicrohttpd-dev ruby

COPY . /app
WORKDIR /app

RUN cd thirdparty/prometheus-client-c && \
	cmake -B build -S prom && \
	make -C build && \
	make -C build install

RUN make test dht

FROM registry.hub.docker.com/library/alpine:3.22
RUN apk add --no-cache libmicrohttpd
COPY --from=build /usr/local/lib/libprom.so /usr/lib/libprom.so

COPY --from=build /app/dht /app/dht

VOLUME /data
EXPOSE 6981
WORKDIR /data

ENTRYPOINT ["/app/dht"]
