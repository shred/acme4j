#!/bin/sh

BAMMBAMM_IP=$(getent hosts bammbamm|cut -d' ' -f1)
echo "My IP is: $BAMMBAMM_IP"

/app -defaultIPv6 "" -defaultIPv4 "$BAMMBAMM_IP"
