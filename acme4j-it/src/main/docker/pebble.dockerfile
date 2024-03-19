FROM ghcr.io/letsencrypt/pebble:latest

FROM alpine
COPY --from=0 /app /app
COPY --from=0 /test /test
COPY pebble.sh /
ENTRYPOINT [ "/pebble.sh" ]
