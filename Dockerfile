FROM alpine:latest

LABEL org.opencontainers.image.authors="Patrick Pokatilo <docker-hub@shyxormz.net>"

ENV LANG C

RUN apk update --no-progress && \
    apk add --no-cache --no-progress \
        bash \
        python3 \
        py3-pip \
        git \
        mercurial && \
    pip3 install --upgrade pip && \
    pip3 install 'requests>=2.8.1'

ADD scripts /opt/resource
