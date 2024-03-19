#!/bin/sh

BAMMBAMM_IP=$(getent hosts bammbamm|cut -d' ' -f1)
echo "DNS server at: $BAMMBAMM_IP"

/app -strict -dnsserver $BAMMBAMM_IP:8053 -config /test/config/pebble-config.json
