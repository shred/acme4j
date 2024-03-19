FROM ghcr.io/letsencrypt/pebble-challtestsrv:latest

FROM alpine
COPY --from=0 /app /app
COPY challtestsrv.sh /
ENTRYPOINT [ "/challtestsrv.sh" ]