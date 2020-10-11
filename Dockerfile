FROM alpine AS build
RUN apk update && apk add \
    musl-dev \
    autoconf \
    automake \
    make \
    gcc \
    tini
COPY . /build
WORKDIR /build
RUN autoreconf -fi && ./configure && make
RUN make DESTDIR=/opt install

FROM alpine
COPY --from=build /opt /
COPY --from=build /sbin/tini /sbin/tini
ENTRYPOINT ["/sbin/tini", "/usr/local/bin/ptunnel-ng"]