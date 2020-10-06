FROM alpine AS build
RUN apk update && apk add \
    musl-dev \
    autoconf \
    automake \
    make \
    gcc
COPY . /build
WORKDIR /build
RUN autoreconf -fi && ./configure && make
RUN make DESTDIR=/opt install

FROM alpine
COPY --from=build /opt /
COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]