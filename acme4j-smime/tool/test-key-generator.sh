#!/bin/bash
#
# acme4j - Java ACME client
#
# Copyright (C) 2022 Richard "Shred" Körber
#   http://acme4j.shredzone.org
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

#
# Generates test keys for S/MIME unit tests.
#
# WARNING: DO NOT USE THIS CODE FOR KEY GENERATION IN PRODUCTION
# ENVIRONMENTS!
#

TARGET=src/test/resources/

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
  -keyout "$TARGET/valid-signer-privkey.pem" -out "$TARGET/valid-signer.pem" \
  -subj "/C=XX/L=Acme City/O=Acme Certificates Ltd/CN=example.com/emailAddress=valid-ca@example.com" \
  -addext "subjectAltName=email:valid-ca@example.com"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
  -keyout "$TARGET/valid-signer-nosan-privkey.pem" -out "$TARGET/valid-signer-nosan.pem" \
  -subj "/C=XX/L=Acme City/O=Acme Certificates Ltd/CN=example.com/emailAddress=valid-ca@example.com"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
  -keyout "$TARGET/invalid-signer-privkey.pem" -out "$TARGET/invalid-signer.pem" \
  -subj "/C=XX/L=Acme City/O=Emca Certificates Ltd/CN=example.com/emailAddress=invalid-ca@example.com" \
  -addext "subjectAltName=email:invalid-ca@example.com"
