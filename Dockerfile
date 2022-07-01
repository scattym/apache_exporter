# Dockerfile for creating a statically-linked golang application using docker's
# multi-stage build feature.
FROM golang:1.18.2-bullseye AS build

ARG http_proxy
ARG https_proxy

ENV GO111MODULE=on

#WORKDIR /usr/src
WORKDIR /usr/local/go/src/
# Copy the source and build the application.
COPY . ./
RUN make

# Copy the statically-linked binary into a scratch container.
FROM scratch
COPY --from=build /usr/local/go/src/apache_exporter .
ENV GOMAXPROCS=1
USER 1000
EXPOSE 5000
ENTRYPOINT ["/apache_exporter"]